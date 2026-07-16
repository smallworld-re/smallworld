// SPDX-License-Identifier: BSD-2-Clause
//! Exception-number model for the MPC866M event controller: `i32` conversions,
//! delivery-priority ordering, async/sync classification, and vector address
//! computation. Kept dependency-free (no `num_enum`/`enum_map`) so the crate's
//! Cargo.toml is unchanged.
use super::Mpc866mIRQn;
use styx_core::prelude::ExceptionNumber;

impl From<Mpc866mIRQn> for ExceptionNumber {
    fn from(irqn: Mpc866mIRQn) -> Self {
        irqn as i32
    }
}

impl TryFrom<ExceptionNumber> for Mpc866mIRQn {
    type Error = ();

    fn try_from(value: ExceptionNumber) -> Result<Self, Self::Error> {
        use Mpc866mIRQn::*;
        Ok(match value {
            1 => SystemReset,
            2 => MachineCheck,
            3 => DSI,
            4 => ISI,
            5 => External,
            6 => Alignment,
            7 => Program,
            8 => FloatingPointUnavailable,
            9 => Decrementer,
            0xC => SystemCall,
            0xD => Trace,
            0xE => FloatingPointAssist,
            0xF => SoftwareEmulation,
            0x10 => InstructionTlbMiss,
            0x11 => DataTlbMiss,
            0x12 => InstructionTlbError,
            0x13 => DataTlbError,
            0x1C => DataBreakpoint,
            0x1D => InstructionBreakpoint,
            0x1E => PeripheralBreakpoint,
            0x1F => NonmaskableDevelopmentPort,
            _ => return Err(()),
        })
    }
}

impl Mpc866mIRQn {
    /// Interrupt handler address. The offset is `irqn * 0x100`, based off the
    /// vector prefix selected by MSR[IP]: `0x0000_0000` (IP=0) or `0xFFF0_0000`
    /// (IP=1). See the MPC866M reference manual, section 6.1.
    pub(crate) fn vector(self, msr_ip: bool) -> u64 {
        let base: u64 = if msr_ip { 0xFFF0_0000 } else { 0x0000_0000 };
        base + (self as u64) * 0x100
    }

    /// Whether SRR0 should hold the *next* instruction address (asynchronous
    /// exceptions and system call) rather than the faulting instruction.
    pub(crate) fn saved_pc_is_next(self) -> bool {
        use Mpc866mIRQn::*;
        matches!(
            self,
            External
                | Decrementer
                | SystemCall
                | Trace
                | PeripheralBreakpoint
                | NonmaskableDevelopmentPort
        )
    }

    /// Whether delivery of this interrupt is gated by MSR[EE] (external and
    /// decrementer requests). All other exceptions are always enabled.
    pub(crate) fn is_maskable(self) -> bool {
        matches!(self, Mpc866mIRQn::External | Mpc866mIRQn::Decrementer)
    }
}

/// Delivery priority, highest first (MPC866M reference manual: "when multiple
/// exception conditions exist"). The pending-exception selector walks this
/// slice, so ordering here *is* the priority policy.
pub(crate) const PRIORITY_ORDER: &[Mpc866mIRQn] = &[
    Mpc866mIRQn::NonmaskableDevelopmentPort,
    Mpc866mIRQn::SystemReset,
    Mpc866mIRQn::MachineCheck,
    // Synchronous (instruction-processing) exceptions.
    Mpc866mIRQn::InstructionTlbMiss,
    Mpc866mIRQn::InstructionTlbError,
    Mpc866mIRQn::InstructionBreakpoint,
    Mpc866mIRQn::SoftwareEmulation,
    Mpc866mIRQn::Program,
    Mpc866mIRQn::Alignment,
    Mpc866mIRQn::SystemCall,
    Mpc866mIRQn::Trace,
    Mpc866mIRQn::DataTlbMiss,
    Mpc866mIRQn::DataTlbError,
    Mpc866mIRQn::DataBreakpoint,
    Mpc866mIRQn::DSI,
    Mpc866mIRQn::ISI,
    Mpc866mIRQn::FloatingPointUnavailable,
    Mpc866mIRQn::FloatingPointAssist,
    // Peripheral breakpoint, then the maskable requests.
    Mpc866mIRQn::PeripheralBreakpoint,
    Mpc866mIRQn::External,
    Mpc866mIRQn::Decrementer,
];
