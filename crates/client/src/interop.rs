//! OpenGL access to D3D11 textures through `WGL_NV_DX_interop2`, for pictures the decoder left
//! on the GPU (see `velora_client_core::GpuPicture`): the window samples the decoder's RGBA
//! texture directly instead of uploading a copy.

use std::ffi::c_void;

use anyhow::{bail, Context as _, Result};
use glow::HasContext;
use glutin::display::{Display, GlDisplay};
use windows::{
    core::Interface,
    Win32::{
        Foundation::{HANDLE, HMODULE},
        Graphics::{
            Direct3D::D3D_DRIVER_TYPE_HARDWARE,
            Direct3D11::{
                D3D11CreateDevice, ID3D11Device, ID3D11Texture2D, D3D11_CREATE_DEVICE_FLAG, D3D11_SDK_VERSION,
            },
        },
    },
};

type OpenDevice = unsafe extern "system" fn(*mut c_void) -> *mut c_void;
type CloseDevice = unsafe extern "system" fn(*mut c_void) -> i32;
type Register = unsafe extern "system" fn(*mut c_void, *mut c_void, u32, u32, u32) -> *mut c_void;
type Unregister = unsafe extern "system" fn(*mut c_void, *mut c_void) -> i32;
type Lock = unsafe extern "system" fn(*mut c_void, i32, *mut *mut c_void) -> i32;

const WGL_ACCESS_READ_ONLY_NV: u32 = 0;
/// Textures kept open at once: the decoder's ring, with room for a size change.
const MAX_OBJECTS: usize = 8;

/// A D3D11 texture as an OpenGL one.
#[derive(Clone, Copy)]
pub struct Shared {
    pub texture: glow::Texture,
    handle: *mut c_void,
}

pub struct Interop {
    close: CloseDevice,
    register: Register,
    unregister: Unregister,
    lock: Lock,
    unlock: Lock,
    /// A D3D11 device of the window's own: the decoder's textures are opened on it, so taking
    /// one only waits for this idle device, not for the decoder at work on the next picture.
    d3d: ID3D11Device,
    /// Its interop handle.
    device: *mut c_void,
    /// Registered textures, by shared handle.
    objects: Vec<(usize, ID3D11Texture2D, Shared)>,
}

impl Interop {
    /// The interop functions and a device for them, when the driver has them. Needs the
    /// context current.
    pub fn load(display: &Display) -> Option<Self> {
        let get = |name: &std::ffi::CStr| {
            let f = display.get_proc_address(name);
            (!f.is_null()).then_some(f)
        };
        // SAFETY: each pointer comes from the driver under its documented name and signature;
        // the device is created with out-pointers to locals.
        unsafe {
            let open = std::mem::transmute::<*const c_void, OpenDevice>(get(c"wglDXOpenDeviceNV")?);
            let mut d3d = None;
            D3D11CreateDevice(
                None,
                D3D_DRIVER_TYPE_HARDWARE,
                HMODULE::default(),
                D3D11_CREATE_DEVICE_FLAG(0),
                None,
                D3D11_SDK_VERSION,
                Some(&mut d3d),
                None,
                None,
            )
            .ok()?;
            let d3d: ID3D11Device = d3d?;
            let device = open(d3d.as_raw());
            if device.is_null() {
                return None;
            }
            Some(Self {
                close: std::mem::transmute::<*const c_void, CloseDevice>(get(c"wglDXCloseDeviceNV")?),
                register: std::mem::transmute::<*const c_void, Register>(get(c"wglDXRegisterObjectNV")?),
                unregister: std::mem::transmute::<*const c_void, Unregister>(get(c"wglDXUnregisterObjectNV")?),
                lock: std::mem::transmute::<*const c_void, Lock>(get(c"wglDXLockObjectsNV")?),
                unlock: std::mem::transmute::<*const c_void, Lock>(get(c"wglDXUnlockObjectsNV")?),
                d3d,
                device,
                objects: Vec::new(),
            })
        }
    }

    /// The OpenGL texture for the shared D3D11 texture `handle`, opened on first use.
    pub fn texture(&mut self, gl: &glow::Context, handle: *mut c_void) -> Result<Shared> {
        if let Some((_, _, shared)) = self.objects.iter().find(|(h, _, _)| *h == handle as usize) {
            return Ok(*shared);
        }
        if self.objects.len() >= MAX_OBJECTS {
            self.unregister_all(gl);
        }
        // SAFETY: a shared handle of a live texture on the same adapter; GL calls on the
        // current context.
        unsafe {
            let mut texture: Option<ID3D11Texture2D> = None;
            self.d3d.OpenSharedResource(HANDLE(handle), &mut texture)?;
            let texture = texture.context("cannot open the shared texture")?;
            let gl_texture = gl.create_texture().map_err(anyhow::Error::msg)?;
            let object = (self.register)(
                self.device,
                texture.as_raw(),
                gl_texture.0.get(),
                glow::TEXTURE_2D,
                WGL_ACCESS_READ_ONLY_NV,
            );
            if object.is_null() {
                gl.delete_texture(gl_texture);
                bail!("the driver cannot share this D3D11 texture with OpenGL");
            }
            let shared = Shared { texture: gl_texture, handle: object };
            self.objects.push((handle as usize, texture, shared));
            Ok(shared)
        }
    }

    /// Runs `draw` with `shared` usable by OpenGL; the D3D11 side waits meanwhile.
    pub fn with<R>(&self, shared: Shared, draw: impl FnOnce() -> R) -> Result<R> {
        let device = self.device;
        let mut handle = shared.handle;
        // SAFETY: a registered object of the open device.
        if unsafe { (self.lock)(device, 1, &mut handle) } == 0 {
            bail!("cannot lock the shared texture");
        }
        let result = draw();
        // SAFETY: as above, locked just before.
        unsafe { (self.unlock)(device, 1, &mut handle) };
        Ok(result)
    }

    fn unregister_all(&mut self, gl: &glow::Context) {
        for (_, _, shared) in self.objects.drain(..) {
            // SAFETY: registered on this device and the current context.
            unsafe {
                (self.unregister)(self.device, shared.handle);
                gl.delete_texture(shared.texture);
            }
        }
    }

    /// Lets go of every texture and the device.
    pub fn release(&mut self, gl: &glow::Context) {
        self.unregister_all(gl);
        if !self.device.is_null() {
            // SAFETY: opened by `load`, closed once.
            unsafe { (self.close)(self.device) };
            self.device = std::ptr::null_mut();
        }
    }
}
