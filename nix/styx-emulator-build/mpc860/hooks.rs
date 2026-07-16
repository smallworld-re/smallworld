// SPDX-License-Identifier: BSD-2-Clause
//! Per-instruction hook for the MPC866M controller.
//!
//! Two jobs, both driven every instruction:
//! 1. Track MSR[EE] so the maskable (external/decrementer) requests are only
//!    delivered while the guest has interrupts enabled.
//! 2. Emulate `rfi` (return-from-interrupt). Under the Unicorn backend `rfi`
//!    would execute natively against QEMU's own SRR0/SRR1, which we never
//!    populate (those SPRs aren't backend-visible), so we intercept the opcode
//!    and restore PC/MSR from the controller's shadow SRRs — the same
//!    "rewrite PC to skip the instruction" trick the SIU uses for `mtspr`.
use styx_core::cpu::arch::ppc32::Ppc32Register;
use styx_core::hooks::CodeHook;
use styx_core::prelude::*;

use super::exception::MSR_EE;
use super::Mpc866mController;

/// PowerPC `rfi` opcode.
const RFI_OPCODE: u32 = 0x4C00_0064;

pub(crate) struct Mpc860CodeHook;

impl CodeHook for Mpc860CodeHook {
    fn call(&mut self, proc: CoreHandle) -> Result<(), UnknownError> {
        let msr = proc.cpu.read_register::<u32>(Ppc32Register::Msr)?;
        let pc = proc.cpu.pc()?;
        let insn = proc.mmu.read_u32_be_phys_code(pc)?;

        let controller = proc.event_controller.get_impl::<Mpc866mController>()?;
        controller.set_maskable_enabled(msr & MSR_EE != 0);

        // `take_return_state` returns owned values, ending the controller borrow
        // before we touch `proc.cpu` again.
        let return_state = if insn == RFI_OPCODE {
            controller.take_return_state()
        } else {
            None
        };

        if let Some((srr0, srr1)) = return_state {
            proc.cpu.write_register(Ppc32Register::Msr, srr1)?;
            proc.cpu.set_pc(srr0 as u64)?;
        }

        Ok(())
    }
}
