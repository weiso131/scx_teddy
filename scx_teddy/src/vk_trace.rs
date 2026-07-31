//! Per-thread Vulkan call rates, read from the layer in the `latency_creater`
//! project (its `game_fps/` directory). The layer intercepts
//! `vkQueuePresentKHR` and `vkQueueSubmit`/`vkQueueSubmit2`, and keeps a
//! high-water mark of each calling thread's calls per second.
//!
//! A separate shm object from the fps buffer, and read differently: there is no
//! handshake. Every field is atomic and the layer maintains the tables on every
//! call, so a reader takes a snapshot whenever it likes and never blocks. The
//! fps path (`metrics/game_fps.rs`) is the one with the request/response
//! protocol; the two share nothing but the layer that writes them.
//!
//! We only ever read, and we never create the object: its absence just means no
//! traced game is running, which is reported as an empty table rather than an
//! error.
//!
//! Env:
//!   VK_TRACE_SHM_NAME   shm name (default "/vk_trace")

use anyhow::{Result, anyhow};
use std::ffi::CString;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU32, Ordering as AtomicOrdering};

/// Must match `PRESENT_MAX_TIDS` / `SUBMIT_MAX_TIDS` in the layer's
/// `game_fps/vk_trace.h`. A thread that finds the table full goes unreported,
/// so its rate reads as 0 — the same value as a thread that makes no Vulkan
/// calls at all.
const PRESENT_MAX_TIDS: usize = 4;
const SUBMIT_MAX_TIDS: usize = 32;

/// Must match `TidSlot` in the layer's `game_fps/vk_trace.h`.
#[repr(C)]
struct TidSlot {
    /// 0 = free slot, else the calling kernel tid.
    tid: AtomicU32,
    /// High-water mark of calls in any one second. Only grows while the slot is
    /// held, so it is valid to load at any time.
    max_per_sec: AtomicU32,
}

/// Must match `VkTraceShm` in the layer's `game_fps/vk_trace.h`.
#[repr(C)]
struct VkTraceShm {
    present_tids: [TidSlot; PRESENT_MAX_TIDS],
    /// `vkQueueSubmit` and `vkQueueSubmit2` both count here.
    submit_tids: [TidSlot; SUBMIT_MAX_TIDS],
}

/// One thread's peak Vulkan call rates, in calls per second.
#[derive(Debug, Clone, Copy)]
pub struct VkTidRate {
    pub tid: i32,
    pub present_rate: u32,
    pub submit_rate: u32,
}

/// The mapping lives for the whole process, so map it once and share it.
struct ShmPtr(*const VkTraceShm);
unsafe impl Send for ShmPtr {}
unsafe impl Sync for ShmPtr {}

static SHM: OnceLock<Option<ShmPtr>> = OnceLock::new();

/// Map the layer's buffer read-only, or report that it is not there.
///
/// Unlike the fps buffer we never pass `O_CREAT`: nothing here writes, so
/// creating the object would only produce an empty one that the layer would
/// later have to adopt. `Ok(None)` means no traced game has run yet.
fn map_shm(name: &str) -> Result<Option<*const VkTraceShm>> {
    let cname = CString::new(name)?;
    let fd = unsafe { libc::shm_open(cname.as_ptr(), libc::O_RDONLY, 0) };
    if fd < 0 {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::ENOENT) {
            return Ok(None);
        }
        return Err(anyhow!("shm_open {name} failed: {err}"));
    }

    // Mapping past the end of the object would SIGBUS on the first read, so
    // check the layer's object is at least as big as the layout we expect.
    let size = std::mem::size_of::<VkTraceShm>();
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut st) } != 0 {
        let err = std::io::Error::last_os_error();
        unsafe { libc::close(fd) };
        return Err(anyhow!("fstat failed: {err}"));
    }
    if (st.st_size as u64) < size as u64 {
        unsafe { libc::close(fd) };
        return Err(anyhow!(
            "shm {name} is {} bytes, expected at least {size} (layout mismatch?)",
            st.st_size
        ));
    }

    let p = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            size,
            libc::PROT_READ,
            libc::MAP_SHARED,
            fd,
            0,
        )
    };
    unsafe { libc::close(fd) };
    if p == libc::MAP_FAILED {
        return Err(anyhow!("mmap failed: {}", std::io::Error::last_os_error()));
    }
    Ok(Some(p as *const VkTraceShm))
}

/// Snapshot both per-thread tables, merged into one entry per tid (a thread
/// that both presents and submits holds a slot in each table).
///
/// Returns an empty vec when the layer has never run. The mapping is attempted
/// once: a game started later will not be picked up until scx_teddy restarts.
///
/// Scans each table in full rather than stopping at the first free slot: a
/// thread that loses the claim CAS moves on to a later index, so an occupied
/// slot can sit past a free one.
pub fn read_tid_rates() -> Result<Vec<VkTidRate>> {
    let cell = SHM.get_or_init(|| {
        let name = std::env::var("VK_TRACE_SHM_NAME")
            .unwrap_or_else(|_| "/vk_trace".to_string());
        match map_shm(&name) {
            Ok(p) => p.map(ShmPtr),
            // A real failure here (a layout mismatch, say) is worth saying out
            // loud once, but it must not stop the scheduler: these are two
            // features out of eleven, and every other one still works.
            Err(e) => {
                eprintln!("vk_trace: {e}; present/submit rates will read as 0");
                None
            }
        }
    });
    let Some(ShmPtr(p)) = cell else {
        return Ok(Vec::new());
    };
    let shm = unsafe { &**p };

    let mut out: Vec<VkTidRate> = Vec::new();
    let mut merge = |slots: &[TidSlot], present: bool| {
        for slot in slots {
            let tid = slot.tid.load(AtomicOrdering::Acquire) as i32;
            if tid == 0 {
                continue;
            }
            let rate = slot.max_per_sec.load(AtomicOrdering::Acquire);
            match out.iter_mut().find(|e| e.tid == tid) {
                Some(e) if present => e.present_rate = rate,
                Some(e) => e.submit_rate = rate,
                None => out.push(VkTidRate {
                    tid,
                    present_rate: if present { rate } else { 0 },
                    submit_rate: if present { 0 } else { rate },
                }),
            }
        }
    };
    merge(&shm.present_tids, true);
    merge(&shm.submit_tids, false);

    Ok(out)
}
