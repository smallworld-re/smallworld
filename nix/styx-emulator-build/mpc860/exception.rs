// SPDX-License-Identifier: BSD-2-Clause
//! Pending/enabled bookkeeping for MPC866M exceptions, plus the MSR bit masks
//! the controller needs. Hand-rolled bitset (no `enum_map`/`bitfield-struct`).
use super::event::PRIORITY_ORDER;
use super::Mpc866mIRQn;

// MSR bit masks (32-bit register, PowerPC big-endian bit numbering, bit 0 = MSB).
// Only MSR_EE gates the current test workloads; the rest shape the delivered-
// interrupt state and follow the MPC866M reference manual, section 6.
pub(crate) const MSR_EE: u32 = 0x0000_8000; // bit 16: external interrupt enable
pub(crate) const MSR_ME: u32 = 0x0000_1000; // bit 19: machine check enable
pub(crate) const MSR_IP: u32 = 0x0000_0040; // bit 25: interrupt prefix (vector base)
pub(crate) const MSR_LE: u32 = 0x0000_0001; // bit 31: little-endian mode
pub(crate) const MSR_ILE: u32 = 0x0000_0020; // bit 26: interrupt little-endian mode

/// Latched ("pending") and enabled bitsets keyed by the `Mpc866mIRQn`
/// discriminant. Every discriminant is in `1..=31`, so a `u32` bitset suffices.
#[derive(Debug, Default)]
pub(crate) struct ExceptionSet {
    latched: u32,
    enabled: u32,
}

impl ExceptionSet {
    pub(crate) fn new() -> Self {
        // Everything except the maskable requests is always enabled; External and
        // Decrementer are toggled by MSR[EE] via `set_maskable_enabled`.
        let mut enabled = 0u32;
        for irqn in PRIORITY_ORDER {
            if !irqn.is_maskable() {
                enabled |= Self::bit(*irqn);
            }
        }
        Self { latched: 0, enabled }
    }

    fn bit(irqn: Mpc866mIRQn) -> u32 {
        1u32 << (irqn as u32)
    }

    /// Mark an exception pending. Idempotent — re-latching an already-pending
    /// request is a no-op (the per-stride decrementer relies on this).
    pub(crate) fn latch(&mut self, irqn: Mpc866mIRQn) {
        self.latched |= Self::bit(irqn);
    }

    pub(crate) fn unlatch(&mut self, irqn: Mpc866mIRQn) {
        self.latched &= !Self::bit(irqn);
    }

    /// Enable/disable the MSR[EE]-gated requests (external, decrementer).
    pub(crate) fn set_maskable_enabled(&mut self, on: bool) {
        let mask = Self::bit(Mpc866mIRQn::External) | Self::bit(Mpc866mIRQn::Decrementer);
        if on {
            self.enabled |= mask;
        } else {
            self.enabled &= !mask;
        }
    }

    /// Highest-priority exception that is both latched and enabled, if any.
    pub(crate) fn first_latched_and_enabled(&self) -> Option<Mpc866mIRQn> {
        PRIORITY_ORDER.iter().copied().find(|irqn| {
            let b = Self::bit(*irqn);
            (self.latched & b != 0) && (self.enabled & b != 0)
        })
    }
}
