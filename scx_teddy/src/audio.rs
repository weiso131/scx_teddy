//! Audio-producer uprobe management.
//!
//! A game that feeds the audio pipeline calls `pa_stream_write` in libpulse.
//! Probing that entry point marks the calling task as an audio producer (a
//! sticky per-task flag in the BPF side), which the classifier then uses as a
//! feature: an audio-driving task sits on a latency-sensitive path much like a
//! render thread.
//!
//! The probe's binary path is only known once there is a target ppid (it lives
//! in that process's mount namespace), so it can't auto-attach at load. `Audio`
//! owns the link and keeps it bound to the current target: call [`Audio::sync`]
//! each loop with the current ppid and it (re)attaches or detaches as the target
//! changes — including a target cleared to 0.

use std::cell::RefCell;
use std::rc::Rc;

use libbpf_rs::{Link, ProgramMut, UprobeOpts};

use crate::Logger;

/// The libpulse symbol the uprobe attaches to.
const PA_STREAM_WRITE: &str = "pa_stream_write";

/// Audio-producer uprobe, kept in sync with the specialization target.
pub struct Audio {
    /// The current uprobe link; dropping it detaches. `None` when no target.
    link: Option<Link>,
    /// The ppid `link` is bound to (0 = none). Lets `sync` skip work when the
    /// target is unchanged and detect a change made by any writer.
    ppid: i32,
}

impl Audio {
    /// A detached audio probe, before any target is known.
    pub fn new() -> Self {
        Self { link: None, ppid: 0 }
    }

    /// libpulse path inside the target process's mount namespace. Built as
    /// /proc/<ppid>/root/... so libbpf resolves the sandboxed (Proton/Wine)
    /// library the game actually loaded, not the host's.
    ///
    /// Steam games load libpulse at this multiarch path; only the game family is
    /// probed for now. If other layouts (native PipeWire builds, other distros)
    /// ever need support, this is the single spot to make configurable.
    fn libpulse_path(ppid: i32) -> String {
        format!("/proc/{ppid}/root/usr/lib/x86_64-linux-gnu/libpulse.so.0")
    }

    /// Bind the probe to `ppid`, (re)attaching when the target changed and
    /// detaching when it went to 0. A no-op when `ppid` already matches the
    /// bound target. Reconcile-style: safe to call every loop iteration.
    ///
    /// Best-effort — an attach failure (no libpulse in that process, symbol
    /// missing) is logged and leaves the probe detached, never aborting the
    /// scheduler. `pid = -1` so the probe fires for every thread mapping that
    /// library (the audio thread is rarely the ppid itself).
    pub fn sync(&mut self, prog: &ProgramMut<'_>, ppid: i32, logger: &Rc<RefCell<Logger>>) {
        if ppid == self.ppid {
            return;
        }
        // Detach the old target first: dropping the link unregisters the probe.
        self.link = None;
        self.ppid = ppid;

        if ppid == 0 {
            logger.borrow_mut().line("audio uprobe: target cleared, detached");
            return;
        }

        let path = Self::libpulse_path(ppid);
        let opts = UprobeOpts {
            func_name: Some(PA_STREAM_WRITE.to_string()),
            ..Default::default()
        };
        match prog.attach_uprobe_with_opts(-1, &path, 0, opts) {
            Ok(link) => {
                self.link = Some(link);
                logger.borrow_mut().line(&format!(
                    "audio uprobe: attached to {path}:{PA_STREAM_WRITE} (ppid {ppid})"
                ));
            }
            Err(e) => logger.borrow_mut().line(&format!(
                "audio uprobe: attach to {path} failed ({e}); no audio signal"
            )),
        }
    }
}
