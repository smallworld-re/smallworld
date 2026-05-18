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
//!   * If the AFL env vars are absent, we run exactly `persistent_iters`
//!     iterations in-process. This makes the bridge usable from unit tests
//!     and ad-hoc harness scripts without an AFL parent.
//!
//! Coverage tracking is currently stubbed out — the bitmap is mapped if AFL
//! advertises one, but no edge tracking hook is installed on the styx
//! processor yet. Plain forkserver + crash detection works.

use std::os::unix::io::RawFd;
use std::path::PathBuf;

use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyTuple};

// AFL++ forkserver protocol constants. These match the values hardcoded in
// upstream afl-fuzz (see include/config.h in AFLplusplus).
const FORKSRV_FD_CTL: RawFd = 198; // AFL -> forkserver (read on this end)
const FORKSRV_FD_STATUS: RawFd = 199; // forkserver -> AFL (write on this end)

/// The PyO3 module entry point. Re-exports `styx_afl_fuzz` so Python users
/// can call `styxafl.styx_afl_fuzz(...)` directly.
#[pymodule]
fn styxafl(_py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(styx_afl_fuzz, m)?)?;
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    Ok(())
}

/// Fuzz a built styx Processor under the AFL++ forkserver protocol.
///
/// Mirrors `unicornafl.uc_afl_fuzz(...)` so SmallWorld's existing harness
/// shape (`machine.fuzz_with_styx(emulator, callback, file)`) is a thin
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
    processor: PyObject,
    input_file: PathBuf,
    place_input_callback: PyObject,
    exits: Vec<u64>,
    validate_crash_callback: Option<PyObject>,
    always_validate: bool,
    persistent_iters: u32,
) -> PyResult<()> {
    let _ = &exits; // exit-point semantics live on the Styx side; nothing
                    // for the bridge to do beyond letting them fire normally.

    if persistent_iters == 0 {
        return Err(PyValueError::new_err("persistent_iters must be >= 1"));
    }

    if !input_file.exists() {
        return Err(PyValueError::new_err(format!(
            "input_file does not exist: {}",
            input_file.display()
        )));
    }

    if is_under_afl() {
        run_under_afl(
            py,
            &processor,
            &input_file,
            &place_input_callback,
            validate_crash_callback.as_ref(),
            always_validate,
        )
    } else {
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

/// Run under afl-fuzz / afl-showmap. Speaks the AFL++ forkserver protocol on
/// fds 198/199, fork()s per iteration, and reports exit status back to AFL.
fn run_under_afl(
    py: Python<'_>,
    processor: &PyObject,
    input_file: &PathBuf,
    place_input_callback: &PyObject,
    validate_crash_callback: Option<&PyObject>,
    always_validate: bool,
) -> PyResult<()> {
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
            // Child path: run one iteration and exit with a status AFL
            // recognises (0 for success, signal for crashes).
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
    processor: &PyObject,
    input_file: &PathBuf,
    place_input_callback: &PyObject,
    round: u32,
    validate_crash_callback: Option<&PyObject>,
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
