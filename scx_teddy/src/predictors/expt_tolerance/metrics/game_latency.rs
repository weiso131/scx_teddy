//! How much delay the game itself can feel, measured from two signals over one
//! shared window: the framerate and the rate the workload feeds the audio
//! pipeline. They come from unrelated sources — video from a Vulkan layer over
//! shared memory, audio from the `pa_stream_write` uprobe over a BPF map — but
//! the experiment only ever asks "did that delay hurt", so they are one metric.
//!
//! **Video.** The layer lives in the `latency_creater` project (its `game_fps/`
//! directory) and intercepts `vkQueuePresentKHR`. Reader-driven
//! request/response: we store the window length in seconds into `request_sec`,
//! then block on FUTEX_WAIT until the layer clears it. The layer notices the
//! nonzero request on its next present, accumulates a window that long, writes
//! the fields, stores `request_sec = 0` and wakes us. It will not write again
//! until we re-arm, so we own the buffer while reading it — no seqlock needed.
//! `request_sec` carries both the request and its parameter, which is why 0 is
//! not a valid window length: it already means idle / result ready. With no game
//! running the layer never clears it, so `measure` stays parked at ~0 CPU.
//!
//! **Audio.** The BPF probe counts `pa_stream_write` calls while we hold a
//! window open; see `audio_expt_t` in intf.h for the handshake. The video side
//! is what times the window: audio is armed before blocking on the layer and
//! closed once the layer answers, so both describe the same stretch of time
//! without needing a second clock. That makes the audio window as long as the
//! layer took, not exactly `secs`, so its rate is divided by the elapsed time we
//! measured rather than by `secs`.
//!
//! With no audio at all — silent game, no probe attached — the rate is 0 in
//! every window, its drop is 0, and the metric degrades to the framerate alone.
//!
//! Env:
//!   LATENCY_SHM_NAME   shm name (default "/game_fps")

use anyhow::{Result, anyhow};
use libbpf_rs::{MapCore, MapFlags, MapHandle};
use std::ffi::CString;
use std::fmt;
use std::ops::AddAssign;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU32, Ordering as AtomicOrdering};
use std::time::{Duration, Instant};

use crate::predictors::expt_tolerance::metric::Metric;

/// Total percentage of the framerate an `expt_wait` may cost across its rounds
/// before it counts as "bad". Summing the drops rather than counting bad rounds
/// lets one ruinous round and a run of mild ones both add up to a verdict.
const FPS_DROP_THRESHOLD: f64 = 20.0;

/// The same, for audio throughput. Separate from the framerate's threshold
/// because the two are different signals on different scales; a dropout is
/// judged on its own terms rather than averaged against the framerate.
const AUDIO_DROP_THRESHOLD: f64 = 20.0;

/// How long to wait for the probe to acknowledge a window close before giving up
/// and taking the count as it stands. Only reached when `pa_stream_write` stops
/// being called at all — a silent or paused game, or an audio thread starved by
/// the injected delay — so it must not be so long that a silent game slows every
/// round by this much.
const AUDIO_ACK_TIMEOUT: Duration = Duration::from_millis(500);

/// How often to re-read the flag while waiting for that acknowledgement.
const AUDIO_ACK_POLL: Duration = Duration::from_millis(5);

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

/// One measured window of the game rendering and producing audio.
#[derive(Debug, Clone)]
pub struct GameLatency {
    pub fps: f64,
    pub min_frametime_ms: f64,
    pub max_frametime_ms: f64,
    pub frame_count: u64,
    /// `pa_stream_write` calls per second over the same window. 0 when the
    /// workload produced no audio, which is indistinguishable from having no
    /// probe attached — both mean "no audio signal to judge".
    pub audio_rate: f64,
}

/// What the injected delay cost the game, summed over an `expt_wait`'s rounds.
/// The two signals stay separate so each is judged against its own threshold.
#[derive(Debug, Clone, Copy, Default)]
pub struct GameDrop {
    pub fps_percent: f64,
    pub audio_percent: f64,
}

impl AddAssign for GameDrop {
    fn add_assign(&mut self, rhs: Self) {
        self.fps_percent += rhs.fps_percent;
        self.audio_percent += rhs.audio_percent;
    }
}

impl fmt::Display for GameDrop {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "fps {:.1}%, audio {:.1}%", self.fps_percent, self.audio_percent)
    }
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

/// Handle on the BPF audio window, handed over by [`attach_audio_map`]. `measure`
/// is an associated function with no state of its own, so the map has to reach it
/// process-wide, the same way the shm mapping above does.
static AUDIO_MAP: OnceLock<MapHandle> = OnceLock::new();

/// Mirrors `audio_expt_t` in intf.h: `{ u32 state; u32 count; }`.
const AUDIO_STATE_IDLE: u32 = 0;
const AUDIO_STATE_RUN: u32 = 1;
const AUDIO_STATE_STOP: u32 = 2;
const AUDIO_VALUE_SIZE: usize = 8;

/// Give the metric the `audio_expt_map` handle. Without it the audio half is
/// simply absent and the metric runs on the framerate alone, so this is
/// best-effort rather than required.
pub fn attach_audio_map(map: MapHandle) {
    let _ = AUDIO_MAP.set(map);
}

fn read_audio(map: &MapHandle) -> Result<(u32, u32)> {
    let key = 0u32.to_ne_bytes();
    match map.lookup(&key, MapFlags::ANY)? {
        Some(v) if v.len() >= AUDIO_VALUE_SIZE => Ok((
            u32::from_ne_bytes(v[..4].try_into().unwrap()),
            u32::from_ne_bytes(v[4..8].try_into().unwrap()),
        )),
        Some(v) => Err(anyhow!("audio_expt value is {} bytes, expected {AUDIO_VALUE_SIZE}", v.len())),
        // A single-entry array map always has index 0.
        None => Err(anyhow!("audio_expt map has no entry 0")),
    }
}

fn write_audio(map: &MapHandle, state: u32, count: u32) -> Result<()> {
    let key = 0u32.to_ne_bytes();
    let mut val = [0u8; AUDIO_VALUE_SIZE];
    val[..4].copy_from_slice(&state.to_ne_bytes());
    val[4..8].copy_from_slice(&count.to_ne_bytes());
    map.update(&key, &val, MapFlags::ANY)?;
    Ok(())
}

/// Open a counting window, discarding whatever the last one left behind.
fn audio_start(map: &MapHandle) -> Result<()> {
    write_audio(map, AUDIO_STATE_RUN, 0)
}

/// Close the window and return what it counted.
///
/// Asks the probe to stop and waits for it to answer `IDLE`, which is what makes
/// the count settled — see `audio_expt_t` in intf.h. When no `pa_stream_write`
/// arrives to deliver that answer the wait times out, and the count is taken as
/// it stands: it is still every write of the window, only its end boundary is as
/// old as the last call.
fn audio_stop(map: &MapHandle) -> Result<u32> {
    let (_, count_before) = read_audio(map)?;
    write_audio(map, AUDIO_STATE_STOP, count_before)?;

    let deadline = Instant::now() + AUDIO_ACK_TIMEOUT;
    loop {
        let (state, count) = read_audio(map)?;
        if state == AUDIO_STATE_IDLE {
            return Ok(count);
        }
        if Instant::now() >= deadline {
            // Take the window back from the probe so the next one starts clean;
            // a probe that wakes later would otherwise still see STOP.
            write_audio(map, AUDIO_STATE_IDLE, count)?;
            return Ok(count);
        }
        std::thread::sleep(AUDIO_ACK_POLL);
    }
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

impl Metric for GameLatency {
    type Drop = GameDrop;

    fn measure(secs: u32) -> Result<Self> {
        // 0 is the protocol's "idle" value, so it cannot request a window; the
        // layer would never clear it and we would park forever.
        if secs == 0 {
            return Err(anyhow!("window length must be > 0 seconds"));
        }
        let shm = shm()?;

        // Open the audio window before arming the layer so it spans everything
        // the frame window does. A failure here only costs the audio half.
        let audio_map = AUDIO_MAP.get();
        let audio_started = match audio_map {
            Some(map) => match audio_start(map) {
                Ok(()) => true,
                Err(e) => {
                    eprintln!("[expt] audio window start failed ({e}); fps only this round");
                    false
                }
            },
            None => false,
        };
        let started_at = Instant::now();

        // Arm a request for a `secs`-long window. The layer picks it up on its
        // next present. It polls the word rather than waiting on it, so a plain
        // store is enough — no FUTEX_WAKE needed on this side.
        shm.request_sec.store(secs, AtomicOrdering::Release);

        // Wait until the layer has measured the window and cleared the request.
        while shm.request_sec.load(AtomicOrdering::Acquire) == secs {
            futex_wait(&shm.request_sec, secs);
        }

        // The layer decides when the window ends, so the audio window is as long
        // as this turned out to be — not `secs`.
        let elapsed = started_at.elapsed().as_secs_f64();
        let audio_rate = match (audio_started, audio_map) {
            (true, Some(map)) => match audio_stop(map) {
                // A window with no measurable length would divide by ~0.
                Ok(count) if elapsed > 0.0 => count as f64 / elapsed,
                Ok(_) => 0.0,
                Err(e) => {
                    eprintln!("[expt] audio window stop failed ({e}); counting 0 this round");
                    0.0
                }
            },
            _ => 0.0,
        };

        // The handshake guarantees the layer is not writing while request == 0.
        Ok(GameLatency {
            fps: shm.fps,
            min_frametime_ms: shm.min_frametime_ms,
            max_frametime_ms: shm.max_frametime_ms,
            frame_count: shm.frame_count,
            audio_rate,
        })
    }

    /// What the injected delay cost each signal, as a percentage, measured
    /// against whichever undelayed window flattered it more: a drop only counts
    /// as far as it holds against both sides, so a game that was already sliding
    /// into a heavier scene does not read as a delay-induced one.
    fn regression(&self, before: &Self, after: &Self) -> Self::Drop {
        // A baseline of zero has nothing to be a fraction of — for audio that is
        // also the silent case, which scores 0 and leaves the framerate to judge.
        let percent = |sample: f64, baseline: f64| {
            if sample.is_nan() || baseline.is_nan() || baseline <= 0.0 {
                return 0.0;
            }
            (baseline - sample) / baseline * 100.0
        };
        GameDrop {
            fps_percent: percent(self.fps, before.fps).min(percent(self.fps, after.fps)),
            audio_percent: percent(self.audio_rate, before.audio_rate)
                .min(percent(self.audio_rate, after.audio_rate)),
        }
    }

    /// Either signal collapsing is enough to call the delay bad: stuttering video
    /// and broken audio are both failures on their own, and scoring them apart
    /// keeps one from being averaged away by the other holding up.
    fn is_bad(total: &Self::Drop) -> bool {
        total.fps_percent >= FPS_DROP_THRESHOLD || total.audio_percent >= AUDIO_DROP_THRESHOLD
    }
}
