//! Game FPS metric, read from the Vulkan layer in the `latency_creater` project
//! (its `game_fps/` directory). The layer intercepts `vkQueuePresentKHR`, and we
//! talk to it over a POSIX shared-memory buffer.
//!
//! Reader-driven request/response: we store the window length in seconds into
//! `request_sec`, then block on FUTEX_WAIT until the layer clears it. The layer
//! notices the nonzero request on its next present, accumulates a window that
//! long, writes the fields, stores `request_sec = 0` and wakes us. It will not
//! write again until we re-arm, so we own the buffer while reading it — no
//! seqlock needed.
//!
//! `request_sec` carries both the request and its parameter, which is why 0 is
//! not a valid window length: it already means idle / result ready.
//!
//! With no game running the layer never clears `request_sec`, so `measure`
//! simply stays parked in FUTEX_WAIT at ~0 CPU.
//!
//! Env:
//!   LATENCY_SHM_NAME   shm name (default "/game_fps")

use anyhow::{Result, anyhow};
use std::cmp::Ordering;
use std::ffi::CString;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU32, Ordering as AtomicOrdering};

use crate::predictors::expt_tolerance::metric::Metric;

/// Must match `FpsShm` in the layer's `game_fps/fps_shm.h` — both sides agree
/// on this layout.
#[repr(C)]
struct FpsShm {
    request_sec: AtomicU32, // >0 = window length in seconds, 0 = idle / result ready
    _pad: u32,
    fps: f64,
    min_frametime_ms: f64,
    max_frametime_ms: f64,
    frame_count: u64,
}

const FPS_EPS: f64 = 0.02;

/// One measured window of game rendering.
#[derive(Debug, Clone)]
pub struct GameFps {
    pub fps: f64,
    pub min_frametime_ms: f64,
    pub max_frametime_ms: f64,
    pub frame_count: u64,
}

/// The mapping lives for the whole process, so map it once and share it. The
/// pointer is only ever used to reach the shm; `measure` has no `self` to hold it.
struct ShmPtr(*mut FpsShm);
unsafe impl Send for ShmPtr {}
unsafe impl Sync for ShmPtr {}

static SHM: OnceLock<ShmPtr> = OnceLock::new();

/// Open the shm object, creating it only if it does not exist yet.
///
/// We cannot just pass `O_CREAT` unconditionally: /dev/shm is a world-writable
/// sticky directory, and with `fs.protected_regular=1` the kernel refuses an
/// `O_CREAT` open of an existing file owned by neither the opener nor the
/// directory owner (EACCES, from `may_create_in_sticky` in fs/namei.c). It
/// compares uids only, so a root reader attaching to the layer's object gets no
/// help from CAP_DAC_OVERRIDE. The check only runs under `open_flag & O_CREAT`,
/// so a plain `O_RDWR` never trips it. This holds in both directions, so it also
/// covers a root layer with an unprivileged reader.
///
/// Returns the fd and whether we created the object.
fn open_shm_fd(cname: &CString) -> Result<(i32, bool)> {
    loop {
        // Try to attach to an existing object without O_CREAT.
        let fd = unsafe { libc::shm_open(cname.as_ptr(), libc::O_RDWR, 0o666) };
        if fd >= 0 {
            return Ok((fd, false));
        }
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::ENOENT) {
            return Err(anyhow!("shm_open failed: {err}"));
        }
        // Doesn't exist yet: create it exclusively so either side may start first.
        let fd = unsafe {
            libc::shm_open(
                cname.as_ptr(),
                libc::O_RDWR | libc::O_CREAT | libc::O_EXCL,
                0o666,
            )
        };
        if fd >= 0 {
            return Ok((fd, true));
        }
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::EEXIST) {
            // The layer created it between our open and create: reopen it.
            continue;
        }
        return Err(anyhow!("shm_open (create) failed: {err}"));
    }
}

/// Map the shm read-write (we set the request flag).
fn map_shm(name: &str) -> Result<*mut FpsShm> {
    let cname = CString::new(name)?;
    let (fd, created) = open_shm_fd(&cname)?;
    let size = std::mem::size_of::<FpsShm>();
    // Only size and chmod an object we created; an existing one belongs to the
    // layer, which already set it up (and may not be ours to chmod).
    if created {
        if unsafe { libc::ftruncate(fd, size as libc::off_t) } != 0 {
            unsafe { libc::close(fd) };
            return Err(anyhow!("ftruncate failed: {}", std::io::Error::last_os_error()));
        }
        unsafe { libc::fchmod(fd, 0o666) };
    } else {
        // We no longer resize an existing object, so check it is big enough:
        // mapping past the end would SIGBUS on the first field read.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(fd, &mut st) } != 0 {
            unsafe { libc::close(fd) };
            return Err(anyhow!("fstat failed: {}", std::io::Error::last_os_error()));
        }
        if (st.st_size as u64) < size as u64 {
            unsafe { libc::close(fd) };
            return Err(anyhow!(
                "shm {name} is {} bytes, expected at least {size} (layout mismatch?)",
                st.st_size
            ));
        }
    }
    let p = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            size,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            fd,
            0,
        )
    };
    unsafe { libc::close(fd) };
    if p == libc::MAP_FAILED {
        return Err(anyhow!("mmap failed: {}", std::io::Error::last_os_error()));
    }
    Ok(p as *mut FpsShm)
}

fn shm() -> Result<&'static FpsShm> {
    let name = std::env::var("LATENCY_SHM_NAME").unwrap_or_else(|_| "/game_fps".to_string());
    if SHM.get().is_none() {
        let p = map_shm(&name)?;
        // A concurrent initializer would leak one mapping; only one caller here.
        let _ = SHM.set(ShmPtr(p));
    }
    let p = SHM.get().ok_or_else(|| anyhow!("shm not mapped"))?.0;
    Ok(unsafe { &*p })
}

/// Block while `word` still equals `expected`. No timeout: if the layer never
/// clears `request_sec` (no game running), we stay parked at ~0 CPU.
fn futex_wait(word: &AtomicU32, expected: u32) {
    unsafe {
        libc::syscall(
            libc::SYS_futex,
            word as *const AtomicU32,
            libc::FUTEX_WAIT,
            expected,
            std::ptr::null::<libc::timespec>(),
        );
    }
    // EAGAIN (already changed) and spurious wakeups just mean "re-check request".
}

impl Metric for GameFps {
    fn measure(secs: u32) -> Result<Self> {
        // 0 is the protocol's "idle" value, so it cannot request a window; the
        // layer would never clear it and we would park forever.
        if secs == 0 {
            return Err(anyhow!("window length must be > 0 seconds"));
        }
        let shm = shm()?;

        // Arm a request for a `secs`-long window. The layer picks it up on its
        // next present. It polls the word rather than waiting on it, so a plain
        // store is enough — no FUTEX_WAKE needed on this side.
        shm.request_sec.store(secs, AtomicOrdering::Release);

        // Wait until the layer has measured the window and cleared the request.
        while shm.request_sec.load(AtomicOrdering::Acquire) == secs {
            futex_wait(&shm.request_sec, secs);
        }

        // The handshake guarantees the layer is not writing while request == 0.
        Ok(GameFps {
            fps: shm.fps,
            min_frametime_ms: shm.min_frametime_ms,
            max_frametime_ms: shm.max_frametime_ms,
            frame_count: shm.frame_count,
        })
    }

    /// Higher FPS is better, so `Less` means this sample rendered worse.
    /// Differences within `FPS_EPS` (relative) are treated as `Equal` so the
    /// game's own jitter is not mistaken for a delay-induced regression. NaN on
    /// either side is reported as indistinguishable.
    fn compare(&self, other: &Self) -> Ordering {
        let (a, b) = (self.fps, other.fps);
        if a.is_nan() || b.is_nan() {
            return Ordering::Equal;
        }
        // Relative tolerance against the larger magnitude, so the threshold
        // scales with the fps level rather than being a fixed absolute gap.
        let tol = FPS_EPS * a.abs().max(b.abs());
        if (a - b).abs() <= tol {
            Ordering::Equal
        } else if a < b {
            Ordering::Less
        } else {
            Ordering::Greater
        }
    }
}
