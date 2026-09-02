// SPDX-License-Identifier: BSD-2-Clause
//! Per-instruction hook for the MPC866M controller.
//!
//! One job: emulate `rfi` (return-from-interrupt). Under the Unicorn backend
//! `rfi` would execute natively against QEMU's own SRR0/SRR1, which we never
//! populate (those SPRs aren't backend-visible), so we intercept the opcode and
//! restore PC/MSR from the controller's shadow SRRs — the same "rewrite PC to
//! skip the instruction" trick the SIU uses for `mtspr`.
//!
//! MSR[EE] is deliberately *not* tracked here. `EventControllerImpl::next`
//! samples it straight from the CPU at delivery time, which is both cheaper
//! (once per stride rather than once per instruction) and correct for an
//! `mtmsr` that closes a critical section as the last instruction of a stride —
//! a hook runs *before* its instruction, so anything it caches is already stale
//! by the time the stride ends.
use styx_core::cpu::arch::ppc32::Ppc32Register;
use styx_core::hooks::CodeHook;
use styx_core::prelude::*;

use super::Mpc866mController;

/// PowerPC `rfi` opcode.
const RFI_OPCODE: u32 = 0x4C00_0064;

pub(crate) struct Mpc860CodeHook;

impl CodeHook for Mpc860CodeHook {
    fn call(&mut self, proc: CoreHandle) -> Result<(), UnknownError> {
        let pc = proc.cpu.pc()?;
        if proc.mmu.read_u32_be_phys_code(pc)? != RFI_OPCODE {
            return Ok(());
        }

        // `take_return_state` returns owned values, so the controller borrow is
        // over before `proc.cpu` is touched again.
        let return_state = proc
            .event_controller
            .get_impl::<Mpc866mController>()?
            .take_return_state();

        if let Some((srr0, srr1)) = return_state {
            proc.cpu.write_register(Ppc32Register::Msr, srr1)?;
            proc.cpu.set_pc(srr0 as u64)?;
        }

        Ok(())
    }
}
