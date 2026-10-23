//! X11 capture through MIT-SHM (the X server writes straight into shared memory, no socket
//! copy) with XDamage so an idle desktop costs neither CPU nor bandwidth.
//!
//! Wayland sessions need the xdg-desktop-portal + PipeWire path (not implemented yet).

use std::{
    ptr,
    time::{Duration, Instant},
};

use anyhow::{bail, ensure, Context, Result};
use x11rb::{
    connection::Connection,
    protocol::{
        damage::{self, ConnectionExt as _},
        shm::ConnectionExt as _,
        xproto::{ConnectionExt as _, ImageFormat, Window},
        Event,
    },
    rust_connection::RustConnection,
    NONE,
};

use super::{Capturer, DisplayRect, Frame};

const GEOMETRY_CHECK_INTERVAL: Duration = Duration::from_secs(1);
const DAMAGE_POLL_INTERVAL: Duration = Duration::from_millis(1);

struct ShmSegment {
    seg: u32,
    addr: *mut u8,
    len: usize,
}

pub struct X11Capturer {
    conn: RustConnection,
    root: Window,
    width: u16,
    height: u16,
    shm: ShmSegment,
    damage: Option<u32>,
    /// Capture on the next call regardless of damage (first frame, resize).
    dirty: bool,
    last_geometry_check: Instant,
}

impl X11Capturer {
    pub fn new() -> Result<Self> {
        let (conn, screen_num) = x11rb::connect(None)
            .context("cannot connect to the X server (is DISPLAY set? Wayland is not supported yet)")?;
        let screen = &conn.setup().roots[screen_num];
        let (root, width, height, depth) =
            (screen.root, screen.width_in_pixels, screen.height_in_pixels, screen.root_depth);

        let bpp = conn.setup().pixmap_formats.iter().find(|f| f.depth == depth).map(|f| f.bits_per_pixel).unwrap_or(0);
        ensure!(bpp == 32 && (depth == 24 || depth == 32), "unsupported X visual: depth {depth}, {bpp} bpp");

        conn.shm_query_version()?.reply().context("X server lacks the MIT-SHM extension")?;
        let shm = attach_shm(&conn, width, height)?;

        let damage = match conn.damage_query_version(1, 1)?.reply() {
            Ok(_) => {
                let id = conn.generate_id()?;
                conn.damage_create(id, root, damage::ReportLevel::NON_EMPTY)?.check()?;
                Some(id)
            }
            Err(_) => {
                tracing::warn!("XDamage unavailable: capturing every frame");
                None
            }
        };

        tracing::info!("X11 capture {width}x{height} (damage: {})", damage.is_some());
        Ok(Self { conn, root, width, height, shm, damage, dirty: true, last_geometry_check: Instant::now() })
    }

    fn check_geometry(&mut self) -> Result<()> {
        self.last_geometry_check = Instant::now();
        let geo = self.conn.get_geometry(self.root)?.reply()?;
        if (geo.width, geo.height) != (self.width, self.height) {
            tracing::info!("display resized to {}x{}", geo.width, geo.height);
            detach_shm(&self.conn, &self.shm);
            self.shm = attach_shm(&self.conn, geo.width, geo.height)?;
            self.width = geo.width;
            self.height = geo.height;
            self.dirty = true;
        }
        Ok(())
    }

    /// Drains pending events; returns whether any damage was reported.
    fn poll_damage(&mut self) -> Result<bool> {
        let mut damaged = false;
        while let Some(event) = self.conn.poll_for_event()? {
            if let Event::DamageNotify(_) = event {
                damaged = true;
            }
        }
        Ok(damaged)
    }
}

impl Capturer for X11Capturer {
    fn rect(&self) -> DisplayRect {
        DisplayRect { x: 0, y: 0, width: self.width as u32, height: self.height as u32 }
    }

    fn capture(&mut self, timeout: Duration) -> Result<Option<Frame<'_>>> {
        if self.last_geometry_check.elapsed() >= GEOMETRY_CHECK_INTERVAL {
            self.check_geometry()?;
        }

        if let Some(damage) = self.damage {
            let deadline = Instant::now() + timeout;
            loop {
                if self.poll_damage()? {
                    self.dirty = true;
                }
                if self.dirty {
                    break;
                }
                if Instant::now() >= deadline {
                    return Ok(None);
                }
                std::thread::sleep(DAMAGE_POLL_INTERVAL);
            }
            // Clear the damage before grabbing so changes made during the grab are reported
            // again on the next call instead of being lost.
            self.conn.damage_subtract(damage, NONE, NONE)?;
        }
        self.dirty = false;

        self.conn
            .shm_get_image(self.root, 0, 0, self.width, self.height, !0, ImageFormat::Z_PIXMAP.into(), self.shm.seg, 0)?
            .reply()
            .context("XShmGetImage failed")?;

        // SAFETY: the segment is mapped for `len` bytes and the X server finished writing it
        // before replying.
        let data = unsafe { std::slice::from_raw_parts(self.shm.addr, self.shm.len) };
        Ok(Some(Frame::new(self.width as u32, self.height as u32, self.width as usize * 4, data)))
    }
}

impl Drop for X11Capturer {
    fn drop(&mut self) {
        detach_shm(&self.conn, &self.shm);
    }
}

fn attach_shm(conn: &RustConnection, width: u16, height: u16) -> Result<ShmSegment> {
    let len = width as usize * height as usize * 4;
    // SAFETY: plain SysV shm calls; results are checked below.
    unsafe {
        let id = libc::shmget(libc::IPC_PRIVATE, len, libc::IPC_CREAT | 0o600);
        if id < 0 {
            bail!("shmget failed: {}", std::io::Error::last_os_error());
        }
        let addr = libc::shmat(id, ptr::null(), 0);
        if addr as isize == -1 {
            let err = std::io::Error::last_os_error();
            libc::shmctl(id, libc::IPC_RMID, ptr::null_mut());
            bail!("shmat failed: {err}");
        }
        let seg = conn.generate_id()?;
        let attached = conn.shm_attach(seg, id as u32, false).map(|c| c.check());
        // Mark for removal now: the kernel frees it once both we and the X server detach,
        // so it cannot leak even if we crash.
        libc::shmctl(id, libc::IPC_RMID, ptr::null_mut());
        if !matches!(attached, Ok(Ok(()))) {
            libc::shmdt(addr);
            bail!("XShmAttach failed (is the X server remote?)");
        }
        Ok(ShmSegment { seg, addr: addr.cast(), len })
    }
}

fn detach_shm(conn: &RustConnection, shm: &ShmSegment) {
    let _ = conn.shm_detach(shm.seg).map(|c| c.check());
    // SAFETY: `addr` came from a successful shmat and is detached only once.
    unsafe {
        libc::shmdt(shm.addr.cast());
    }
}
