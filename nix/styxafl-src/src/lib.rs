//! AFL++ forkserver bridge for the Styx emulator, exposed to Python.
//!
//! This crate is the Styx counterpart to `unicornafl`. It is consumed from
//! Python via `styxafl.styx_afl_fuzz(...)`. The Python wrapper hands us:
//!   * the live `styx_emulator.Processor` instance (as an opaque `PyAny`),
//!   * the AFL input file path (the seed AFL is mutating each iteration),
//!   * a Python callback that copies the new input into emulator memory,
//!   * the list of "normal" exit points,
//!   * an optional callback that validates whether a crash is interesting,
//!   * configuration knobs (`always_validate`, `persistent_iters`).
//!
//! Execution model:
//!   * If the process is launched under `afl-fuzz` / `afl-showmap` (detected
//!     via the `__AFL_SHM_ID` environment variable), we speak the AFL++
//!     forkserver protocol on fds 198/199: write a 4-byte hello, accept
//!     fork commands, fork+wait per iteration, and report exit status.
//!     We also attach the AFL coverage bitmap and install a styx `BlockHook`
//!     so each basic-block entry updates the shared edge map.
//!   * If the AFL env vars are absent, we run exactly `persistent_iters`
//!     iterations in-process. This makes the bridge usable from unit tests
//!     and ad-hoc harness scripts without an AFL parent.
//!
//! Edge coverage uses styx's native `BlockHook` (the same per-basic-block
//! notification primitive that `styx-fuzzer`'s trace plugin consumes) and
//! the canonical AFL bitmap update: `map[prev_loc ^ cur_loc]++; prev_loc =
//! cur_loc >> 1`. `prev_loc` is reset to 0 before every iteration so edges
//! don't leak across fuzz inputs.

use std::os::unix::io::RawFd;
use std::path::PathBuf;
use std::sync::atomic::{AtomicPtr, AtomicU32, AtomicUsize, Ordering};

use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyTuple};

// AFL++ forkserver protocol constants. These match the values hardcoded in
// upstream afl-fuzz (see include/config.h in AFLplusplus).
const FORKSRV_FD_CTL: RawFd = 198; // AFL -> forkserver (read on this end)
const FORKSRV_FD_STATUS: RawFd = 199; // forkserver -> AFL (write on this end)

// AFL++ default coverage-bitmap size (1 << 16 = 65536). AFL_MAP_SIZE may
// override this; we honour it on attach.
const DEFAULT_MAP_SIZE: usize = 1 << 16;

/// Shared coverage bitmap (the AFL `__afl_area_ptr`). Null when not running
/// under AFL or when the shmat() failed.
static BITMAP_PTR: AtomicPtr<u8> = AtomicPtr::new(std::ptr::null_mut());
/// Size of the bitmap pointed to by `BITMAP_PTR`, in bytes. Always a power
/// of two so the AFL edge index can be masked with `MAP_SIZE - 1`.
static MAP_SIZE: AtomicUsize = AtomicUsize::new(0);
/// AFL's `prev_loc` state. Reset to 0 at the top of each iteration so that
/// the first edge of a new fuzz input does not carry an edge id over from
/// the previous input.
static PREV_LOC: AtomicU32 = AtomicU32::new(0);

/// The PyO3 module entry point. Re-exports `styx_afl_fuzz` so Python users
/// can call `styxafl.styx_afl_fuzz(...)` directly.
#[pymodule]
fn styxafl(_py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(styx_afl_fuzz, m)?)?;
    // _coverage_on_block is the BlockHook callback we install on the styx
    // processor; it has to be reachable as a Python-callable so the styx
    // BlockHook wrapper can invoke it. It is an implementation detail and
    // should not be called directly by user code.
    m.add_function(wrap_pyfunction!(_coverage_on_block, m)?)?;
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    Ok(())
}

/// Fuzz a built styx Processor under the AFL++ forkserver protocol.
///
/// Mirrors `unicornafl.uc_afl_fuzz(...)` so SmallWorld's existing harness
/// shape (`machine.fuzz_with_file(emulator, callback, file)`) is a thin
/// wrapper around this call.
#[pyfunction]
#[pyo3(signature = (
    processor,
    input_file,
    place_input_callback,
    exits,
    validate_crash_callback=None,
    always_validate=false,
    persistent_iters=1u32,
))]
#[allow(clippy::too_many_arguments)]
fn styx_afl_fuzz(
    py: Python<'_>,
    processor: Py<PyAny>,
    input_file: PathBuf,
    place_input_callback: Py<PyAny>,
    exits: Vec<u64>,
    validate_crash_callback: Option<Py<PyAny>>,
    always_validate: bool,
    persistent_iters: u32,
) -> PyResult<()> {
    let _ = &exits; // exit-point semantics live on the Styx side; nothing
                    // for the bridge to do beyond letting them fire normally.

    if persistent_iters == 0 {
        return Err(PyValueError::new_err("persistent_iters must be >= 1"));
    }

    if is_under_afl() {
        // Don't eagerly check that input_file exists: under the AFL++
        // forkserver protocol, AFL writes the .cur_input file between
        // forkserver iterations, so it may not exist at the moment this
        // function is first entered. ``run_one_iteration`` reads the file
        // fresh each round and will surface a clear error if it's missing.
        //
        // We branch on whether the forkserver control/status fds are
        // actually open in our process. afl-fuzz / afl-showmap-with-forkserver
        // open them; afl-showmap without forkserver mode and ad-hoc tools
        // that only set __AFL_SHM_ID do not. In the latter case we just run
        // one iteration in-process — the coverage bitmap is still attached
        // and the BlockHook still fires, so the caller gets a populated
        // shmem image without us hanging on a non-existent control pipe.
        attach_afl_bitmap();
        install_coverage_block_hook(py, &processor)?;

        if fd_is_open(FORKSRV_FD_CTL) && fd_is_open(FORKSRV_FD_STATUS) {
            run_under_afl(
                py,
                &processor,
                &input_file,
                &place_input_callback,
                validate_crash_callback.as_ref(),
                always_validate,
            )
        } else {
            coverage_reset_iteration();
            run_one_iteration(
                py,
                &processor,
                &input_file,
                &place_input_callback,
                0,
                validate_crash_callback.as_ref(),
                always_validate,
            )?;
            Ok(())
        }
    } else {
        if !input_file.exists() {
            return Err(PyValueError::new_err(format!(
                "input_file does not exist: {}",
                input_file.display()
            )));
        }
        for round in 0..persistent_iters {
            run_one_iteration(
                py,
                &processor,
                &input_file,
                &place_input_callback,
                round,
                validate_crash_callback.as_ref(),
                always_validate,
            )?;
        }
        Ok(())
    }
}

/// Detect whether the current process was launched by AFL.
fn is_under_afl() -> bool {
    // AFL++ always sets __AFL_SHM_ID on the child. The newer LLVM-based
    // variants additionally set __AFL_SHM_FUZZ_ID. Either is enough to
    // know we should speak the forkserver protocol.
    std::env::var("__AFL_SHM_ID").is_ok() || std::env::var("__AFL_SHM_FUZZ_ID").is_ok()
}

/// Returns whether `fd` is a valid file descriptor in the current process.
/// Used to distinguish afl-fuzz (forkserver fds open) from afl-showmap
/// running without `-O` (env vars set but no forkserver fds).
fn fd_is_open(fd: RawFd) -> bool {
    unsafe { libc::fcntl(fd, libc::F_GETFD) >= 0 }
}

/// Run under afl-fuzz / afl-showmap. Speaks the AFL++ forkserver protocol on
/// fds 198/199, fork()s per iteration, and reports exit status back to AFL.
fn run_under_afl(
    py: Python<'_>,
    processor: &Py<PyAny>,
    input_file: &PathBuf,
    place_input_callback: &Py<PyAny>,
    validate_crash_callback: Option<&Py<PyAny>>,
    always_validate: bool,
) -> PyResult<()> {
    // The SHM attach and BlockHook install happen in the caller now, so
    // both the forkserver and the showmap-style single-shot paths see them.

    // Step 1: hello handshake. AFL waits to read 4 bytes on FORKSRV_FD_STATUS
    // before it knows the forkserver is up.
    let hello = [0u8; 4];
    write_exact(FORKSRV_FD_STATUS, &hello).map_err(|e| {
        PyRuntimeError::new_err(format!("forkserver hello write failed: {e}"))
    })?;

    let mut round: u32 = 0;
    loop {
        // Step 2: wait for AFL to ask for the next iteration. AFL writes a
        // 4-byte (often zeroed) message. If the read returns 0 bytes, AFL
        // closed the pipe and we should exit cleanly.
        let mut cmd_buf = [0u8; 4];
        match read_exact(FORKSRV_FD_CTL, &mut cmd_buf) {
            Ok(0) => return Ok(()),
            Ok(_) => {}
            Err(e) => {
                return Err(PyRuntimeError::new_err(format!(
                    "forkserver control read failed: {e}"
                )))
            }
        }

        // Step 3: fork. The child runs the iteration and exits. The parent
        // reports the child's pid + wait status back to AFL.
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            return Err(PyRuntimeError::new_err(format!(
                "fork() failed: errno={}",
                std::io::Error::last_os_error()
            )));
        }
        if pid == 0 {
            // Child path: reset per-iteration coverage state, run one
            // iteration, and exit with a status AFL recognises (0 for
            // success, signal for crashes). AFL zeroes the bitmap between
            // iterations in the parent, so we re-stamp the "non-empty"
            // canary byte here to keep AFL from declaring the run
            // uninstrumented when the input takes a fast-reject path that
            // doesn't enter any new basic blocks.
            coverage_reset_iteration();
            let outcome = run_one_iteration(
                py,
                processor,
                input_file,
                place_input_callback,
                round,
                validate_crash_callback,
                always_validate,
            );
            match outcome {
                Ok(IterationOutcome::Normal) => unsafe { libc::_exit(0) },
                Ok(IterationOutcome::Skip) => unsafe { libc::_exit(0) },
                Ok(IterationOutcome::Crash) => {
                    // Raise SIGABRT so AFL records this as a crash. Using
                    // raise+default-handler matches what unicornafl does on
                    // styx-equivalent fault paths.
                    unsafe { libc::raise(libc::SIGABRT) };
                    unsafe { libc::_exit(1) };
                }
                Err(_) => unsafe { libc::_exit(1) },
            }
        }

        // Parent path: tell AFL which pid is running, then wait.
        let pid_bytes = (pid as i32).to_le_bytes();
        write_exact(FORKSRV_FD_STATUS, &pid_bytes).map_err(|e| {
            PyRuntimeError::new_err(format!("forkserver pid write failed: {e}"))
        })?;

        let mut status: libc::c_int = 0;
        let waited = unsafe { libc::waitpid(pid, &mut status, 0) };
        if waited < 0 {
            return Err(PyRuntimeError::new_err(format!(
                "waitpid({pid}) failed: errno={}",
                std::io::Error::last_os_error()
            )));
        }

        let status_bytes = (status as i32).to_le_bytes();
        write_exact(FORKSRV_FD_STATUS, &status_bytes).map_err(|e| {
            PyRuntimeError::new_err(format!("forkserver status write failed: {e}"))
        })?;

        round = round.wrapping_add(1);
    }
}

#[derive(Debug, Clone, Copy)]
enum IterationOutcome {
    /// Processor ran to a normal exit point or instruction limit.
    Normal,
    /// User input was rejected by `place_input_callback` returning False.
    Skip,
    /// The `EmulationReport` came back with `is_fatal == true` (or a custom
    /// `validate_crash_callback` returned truthy). The caller is responsible
    /// for translating this into a signal-style exit when running under AFL.
    Crash,
}

/// Drive one fuzz iteration: read the seed file, hand it to the user's
/// place_input_callback, then `start()` and `wait_for_stop()` the processor.
fn run_one_iteration(
    py: Python<'_>,
    processor: &Py<PyAny>,
    input_file: &PathBuf,
    place_input_callback: &Py<PyAny>,
    round: u32,
    validate_crash_callback: Option<&Py<PyAny>>,
    always_validate: bool,
) -> PyResult<IterationOutcome> {
    let input_bytes = std::fs::read(input_file).map_err(|e| {
        PyRuntimeError::new_err(format!("failed to read input file: {e}"))
    })?;

    // place_input_callback(processor, input_bytes, round, data=None)
    let cb_args = PyTuple::new(
        py,
        [
            processor.clone_ref(py),
            PyBytes::new(py, &input_bytes).into(),
            round.into_pyobject(py)?.unbind().into(),
            py.None(),
        ],
    )?;
    let accept = place_input_callback.call1(py, cb_args)?;

    // The unicornafl protocol says: callback returns False to skip this
    // input, None/True to accept and continue.
    let accept_b: bool = if accept.is_none(py) {
        true
    } else {
        accept.extract::<bool>(py).unwrap_or(true)
    };
    if !accept_b {
        return Ok(IterationOutcome::Skip);
    }

    // Run the processor.
    processor.call_method0(py, "start")?;
    let report = processor.call_method0(py, "wait_for_stop")?;

    let is_fatal: bool = report
        .getattr(py, "is_fatal")
        .ok()
        .and_then(|v| v.extract::<bool>(py).ok())
        .unwrap_or(false);

    let should_validate = always_validate || is_fatal;
    let mut treat_as_crash = is_fatal;

    if should_validate {
        if let Some(cb) = validate_crash_callback {
            // The validate callback receives the styx EmulationReport. A
            // truthy return value (or None) means "record this as a crash";
            // an explicit False means "ignore".
            let cb_ret = cb.call1(py, (report,))?;
            let keep: bool = if cb_ret.is_none(py) {
                is_fatal
            } else {
                cb_ret.extract::<bool>(py).unwrap_or(is_fatal)
            };
            treat_as_crash = keep;
        }
    }

    if treat_as_crash {
        Ok(IterationOutcome::Crash)
    } else {
        Ok(IterationOutcome::Normal)
    }
}

// ---------------------------------------------------------------------------
// Coverage tracking.
//
// The AFL coverage protocol expects the child process to maintain a byte
// array shared with afl-fuzz (the "edge map") and to bump entries based on
// pairs of (previous edge id, current edge id). We piggy-back on styx's
// `BlockHook`, the same per-basic-block notification primitive `styx-fuzzer`
// uses for its trace-driven coverage map, and run the standard AFL update
// in our PyO3 callback.
// ---------------------------------------------------------------------------

/// Attach the AFL coverage shared-memory segment advertised by `__AFL_SHM_ID`
/// and stamp the "instrumented" canary so AFL's calibration accepts us even
/// on test cases that don't fire any blocks.
///
/// Failures here are non-fatal — the bridge still drives fuzz iterations,
/// they just won't report coverage. AFL's calibration will then bail with
/// `No instrumentation detected`, which is the symptom callers see when
/// shmat misbehaves.
fn attach_afl_bitmap() {
    let id_str = match std::env::var("__AFL_SHM_ID") {
        Ok(s) => s,
        Err(_) => return, // No coverage SHM advertised; nothing to do.
    };

    // The id AFL puts in the env is a SystemV shmid (decimal integer). This
    // matches what `afl-sharedmem.c` writes and what LibAFL / unicornafl
    // expect to parse. A future POSIX-shm (USEMMAP) AFL build would put a
    // path here instead; we'd need to branch on `id_str.parse::<i32>()`
    // succeeding to support that. Stock AFL++ in nixpkgs uses sysv.
    let shmid: libc::c_int = match id_str.parse() {
        Ok(n) => n,
        Err(_) => {
            log::warn!("__AFL_SHM_ID is not an integer: {id_str:?}");
            return;
        }
    };

    let map_size = std::env::var("AFL_MAP_SIZE")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .map(|n| if n == 0 { DEFAULT_MAP_SIZE } else { n })
        .unwrap_or(DEFAULT_MAP_SIZE);

    // SAFETY: shmat with shmaddr=NULL asks the kernel to pick the mapping
    // address; flag 0 = read/write. Returns (void*)-1 on error.
    let addr = unsafe { libc::shmat(shmid, std::ptr::null(), 0) };
    if addr as isize == -1 {
        log::warn!(
            "shmat(__AFL_SHM_ID={shmid}) failed: {}",
            std::io::Error::last_os_error()
        );
        return;
    }

    BITMAP_PTR.store(addr as *mut u8, Ordering::Release);
    MAP_SIZE.store(map_size, Ordering::Release);

    // The "non-empty bitmap" canary. AFL's calibration check is literally
    // "is any byte in the bitmap non-zero after the first iteration?"; if
    // not, it aborts with FATAL("No instrumentation detected"). Marking
    // byte 0 guarantees we always pass that check.
    unsafe {
        std::ptr::write_volatile(addr as *mut u8, 1u8);
    }
}

/// Reset the per-iteration coverage state. Called inside the AFL child path
/// before each `run_one_iteration`. The parent zeroes the bitmap between
/// iterations, so all we have to do here is clear `prev_loc` (so the first
/// block of this iteration doesn't get an edge-id from the previous one)
/// and re-stamp the calibration canary into the freshly-zeroed map.
fn coverage_reset_iteration() {
    PREV_LOC.store(0, Ordering::Release);
    let ptr = BITMAP_PTR.load(Ordering::Acquire);
    if !ptr.is_null() {
        unsafe { std::ptr::write_volatile(ptr, 1u8) };
    }
}

/// Map a basic-block-entry PC into a slot id in the AFL edge map.
///
/// A simple two-round multiplicative+xor-shift mixer is plenty for AFL's
/// purposes — bucket collisions just under-count edges, they don't break
/// correctness. The constants come from the well-known
/// [splittable64](https://nullprogram.com/blog/2018/07/31/) hash family.
fn pc_to_slot(pc: u64) -> u32 {
    let mut h = pc;
    h ^= h >> 30;
    h = h.wrapping_mul(0xBF58_476D_1CE4_E5B9);
    h ^= h >> 27;
    h = h.wrapping_mul(0x94D0_49BB_1331_11EB);
    h ^= h >> 31;
    h as u32
}

/// Canonical AFL edge-map update for a single basic-block entry. Does
/// nothing if no AFL bitmap is attached.
fn record_block_entry(pc: u64) {
    let ptr = BITMAP_PTR.load(Ordering::Acquire);
    if ptr.is_null() {
        return;
    }
    let map_size = MAP_SIZE.load(Ordering::Acquire);
    if map_size == 0 {
        return;
    }
    // `map_size` is usually a power of two (65536), but AFL_MAP_SIZE can
    // be arbitrary; use `%` instead of a mask so we don't mis-index for
    // non-power-of-two map sizes.
    let cur_loc = (pc_to_slot(pc) as usize) % map_size;
    let prev = PREV_LOC.load(Ordering::Relaxed) as usize;
    let idx = (prev ^ cur_loc) % map_size;
    // SAFETY: the AFL shmem is at least `map_size` bytes and `idx <
    // map_size`. The child is single-threaded so the increment is not
    // racy.
    unsafe {
        let slot = ptr.add(idx);
        *slot = (*slot).wrapping_add(1);
    }
    // AFL stores the previous edge id shifted right by 1 so the A->B and
    // B->A edges get different bitmap slots.
    PREV_LOC.store((cur_loc >> 1) as u32, Ordering::Relaxed);
}

/// PyO3 callback wired into a styx `BlockHook`. Styx invokes this with
/// `(processor_core, address, size)` at every basic-block entry; we only
/// need the address.
#[pyfunction]
fn _coverage_on_block(_cpu: Py<PyAny>, address: u64, _size: u32) {
    record_block_entry(address);
}

/// Install the AFL coverage `BlockHook` on the styx processor. Reuses
/// styx's native per-basic-block hook primitive — the same one
/// `styx-fuzzer`'s trace plugin uses to drive its LibAFL-backed coverage
/// map — so we don't have to reinvent the per-block notification path.
fn install_coverage_block_hook(py: Python<'_>, processor: &Py<PyAny>) -> PyResult<()> {
    let hooks_mod = py.import("styx_emulator.cpu.hooks")?;
    let block_hook_cls = hooks_mod.getattr("BlockHook")?;
    let cb = wrap_pyfunction!(_coverage_on_block, py)?;
    let hook_instance = block_hook_cls.call1((cb,))?;
    processor.call_method1(py, "add_hook", (hook_instance,))?;
    Ok(())
}

/// Read exactly `buf.len()` bytes from `fd`, looping past EINTR / short reads.
/// Returns the number of bytes actually read — 0 means the pipe was closed.
fn read_exact(fd: RawFd, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut total = 0usize;
    while total < buf.len() {
        let n = unsafe {
            libc::read(
                fd,
                buf.as_mut_ptr().add(total) as *mut libc::c_void,
                buf.len() - total,
            )
        };
        if n < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err);
        }
        if n == 0 {
            // EOF — caller treats this as "AFL went away".
            return Ok(total);
        }
        total += n as usize;
    }
    Ok(total)
}

/// Write exactly `buf.len()` bytes to `fd`, looping past EINTR / short writes.
fn write_exact(fd: RawFd, buf: &[u8]) -> std::io::Result<()> {
    let mut total = 0usize;
    while total < buf.len() {
        let n = unsafe {
            libc::write(
                fd,
                buf.as_ptr().add(total) as *const libc::c_void,
                buf.len() - total,
            )
        };
        if n < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err);
        }
        total += n as usize;
    }
    Ok(())
}
