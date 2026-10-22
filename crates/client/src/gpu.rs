//! GPU presentation: the decoded planes go up as textures (I420: three one-channel ones; NV12
//! from a GPU decoder: luma plus a two-channel chroma one), and a shader
//! converts them (BT.601 limited range, like the host) while scaling with bilinear filtering
//! into the letterboxed viewport. Frees the CPU of the color conversion and the per-pixel
//! scaling of the software path, and scales smoothly instead of pixel by pixel. Pictures the
//! decoder left on the GPU (RGBA, see `interop`) are sampled where they are, with no upload.

use std::num::NonZeroU32;

use anyhow::{Context as _, Result};
use glow::HasContext;
use glutin::{
    config::ConfigTemplateBuilder,
    context::{ContextApi, ContextAttributesBuilder, NotCurrentGlContext, PossiblyCurrentContext, Version},
    display::{Display, DisplayApiPreference, GlDisplay},
    surface::{GlSurface, Surface, SurfaceAttributesBuilder, SwapInterval, WindowSurface},
};
use raw_window_handle::{HasDisplayHandle, HasWindowHandle};
use velora_client_core::{Chroma, VideoFrame};
use winit::window::Window;

use crate::render::Viewport;

const VERTEX: &str = r#"
out vec2 uv;
void main() {
    // A quad as a triangle strip, from the vertex index alone: no buffers to set up.
    vec2 corner = vec2(float(gl_VertexID & 1), float(gl_VertexID >> 1));
    uv = corner;
    gl_Position = vec4(corner.x * 2.0 - 1.0, 1.0 - corner.y * 2.0, 0.0, 1.0);
}
"#;

const FRAGMENT: &str = r#"
uniform sampler2D luma;
uniform sampler2D cb;
uniform sampler2D cr;
// 0: I420 planes, 1: NV12 (chroma interleaved), 2: RGB already.
uniform int mode;
in vec2 uv;
out vec4 color;
void main() {
    if (mode == 2) {
        color = vec4(texture(luma, uv).rgb, 1.0);
        return;
    }
    float y = 1.164383 * (texture(luma, uv).r - 0.062745);
    float u = texture(cb, uv).r - 0.5;
    float v = (mode == 1 ? texture(cb, uv).g : texture(cr, uv).r) - 0.5;
    color = vec4(y + 1.596027 * v, y - 0.391762 * u - 0.812968 * v, y + 2.017232 * u, 1.0);
}
"#;

pub struct Gpu {
    // Dropped in this order: GL objects need the context, which needs the surface's display.
    gl: glow::Context,
    program: glow::Program,
    vao: glow::VertexArray,
    /// Luma, then the two chroma planes.
    textures: [glow::Texture; 3],
    /// Size and chroma layout of the picture in the textures.
    picture: (u32, u32),
    chroma: Chroma,
    mode: Option<glow::UniformLocation>,
    /// The decoder's texture, while the picture is one left on the GPU.
    #[cfg(all(windows, feature = "ffmpeg"))]
    shared: Option<crate::interop::Shared>,
    #[cfg(all(windows, feature = "ffmpeg"))]
    interop: Option<crate::interop::Interop>,
    surface: Surface<WindowSurface>,
    context: PossiblyCurrentContext,
    /// The drawable's size, to resize it with the window.
    drawable: (u32, u32),
}

impl Gpu {
    pub fn new(window: &Window) -> Result<Self> {
        let raw_display = window.display_handle()?.as_raw();
        let raw_window = window.window_handle()?.as_raw();
        #[cfg(windows)]
        let preference = DisplayApiPreference::WglThenEgl(Some(raw_window));
        #[cfg(not(windows))]
        let preference = DisplayApiPreference::Egl;
        // SAFETY: the handles belong to a live window, which the app keeps alive longer than
        // this presenter.
        let display = unsafe { Display::new(raw_display, preference) }.context("opening the OpenGL display")?;
        let template = ConfigTemplateBuilder::new().compatible_with_native_window(raw_window).build();
        // SAFETY: as above.
        let config = unsafe { display.find_configs(template) }?.next().context("no OpenGL configuration")?;
        let desktop = ContextAttributesBuilder::new()
            .with_context_api(ContextApi::OpenGl(Some(Version::new(3, 3))))
            .build(Some(raw_window));
        let embedded = ContextAttributesBuilder::new()
            .with_context_api(ContextApi::Gles(Some(Version::new(3, 0))))
            .build(Some(raw_window));
        // SAFETY: as above.
        let context = unsafe {
            display.create_context(&config, &desktop).or_else(|_| display.create_context(&config, &embedded))
        }
        .context("creating an OpenGL 3.3 or OpenGL ES 3.0 context")?;
        let size = window.inner_size();
        let (w, h) = (size.width.max(1), size.height.max(1));
        let attributes = SurfaceAttributesBuilder::<WindowSurface>::new().build(raw_window, nonzero(w), nonzero(h));
        // SAFETY: as above.
        let surface = unsafe { display.create_window_surface(&config, &attributes) }?;
        let context = context.make_current(&surface)?;
        // Each frame shows as soon as it is drawn: waiting for the screen's refresh would add
        // up to a refresh of latency to every remote frame.
        let _ = surface.set_swap_interval(&context, SwapInterval::DontWait);
        // SAFETY: the context is current on this thread.
        let gl = unsafe { glow::Context::from_loader_function_cstr(|name| display.get_proc_address(name)) };
        // SAFETY: GL calls on the current context, with objects created right here.
        unsafe {
            let header = if gl.version().is_embedded {
                "#version 300 es\nprecision mediump float;\n"
            } else {
                "#version 330 core\n"
            };
            let program = link(&gl, &format!("{header}{VERTEX}"), &format!("{header}{FRAGMENT}"))?;
            gl.use_program(Some(program));
            let vao = gl.create_vertex_array().map_err(anyhow::Error::msg)?;
            let mut textures = Vec::new();
            for (unit, name) in ["luma", "cb", "cr"].into_iter().enumerate() {
                let texture = gl.create_texture().map_err(anyhow::Error::msg)?;
                gl.active_texture(glow::TEXTURE0 + unit as u32);
                gl.bind_texture(glow::TEXTURE_2D, Some(texture));
                for (param, value) in [
                    (glow::TEXTURE_MIN_FILTER, glow::LINEAR),
                    (glow::TEXTURE_MAG_FILTER, glow::LINEAR),
                    (glow::TEXTURE_WRAP_S, glow::CLAMP_TO_EDGE),
                    (glow::TEXTURE_WRAP_T, glow::CLAMP_TO_EDGE),
                ] {
                    gl.tex_parameter_i32(glow::TEXTURE_2D, param, value as i32);
                }
                gl.uniform_1_i32(gl.get_uniform_location(program, name).as_ref(), unit as i32);
                textures.push(texture);
            }
            // Plane rows are packed: odd widths are not 4-byte aligned.
            gl.pixel_store_i32(glow::UNPACK_ALIGNMENT, 1);
            tracing::info!(
                "drawing with {} ({})",
                gl.get_parameter_string(glow::RENDERER),
                gl.get_parameter_string(glow::VERSION)
            );
            let mode = gl.get_uniform_location(program, "mode");
            #[cfg(all(windows, feature = "ffmpeg"))]
            let interop = crate::interop::Interop::load(&display);
            Ok(Self {
                gl,
                program,
                vao,
                textures: textures.try_into().expect("three textures"),
                picture: (0, 0),
                chroma: Chroma::Planar,
                mode,
                #[cfg(all(windows, feature = "ffmpeg"))]
                shared: None,
                #[cfg(all(windows, feature = "ffmpeg"))]
                interop,
                surface,
                context,
                drawable: (w, h),
            })
        }
    }

    /// Whether pictures left on the GPU can be shown (the driver shares D3D11 textures).
    pub fn zero_copy(&self) -> bool {
        #[cfg(all(windows, feature = "ffmpeg"))]
        return self.interop.is_some();
        #[cfg(not(all(windows, feature = "ffmpeg")))]
        false
    }

    /// Puts a new picture in the textures, or for one left on the GPU, takes its texture.
    /// Fails when such a picture cannot be shown: send pictures in memory from then on.
    pub fn upload(&mut self, frame: &VideoFrame) -> Result<()> {
        if let Some(picture) = &frame.gpu {
            #[cfg(all(windows, feature = "ffmpeg"))]
            {
                let interop = self.interop.as_mut().context("no D3D11 interop")?;
                let shared = interop.texture(&self.gl, picture.shared_handle());
                let shared = match shared {
                    Ok(shared) => shared,
                    Err(e) => {
                        self.interop = None;
                        return Err(e);
                    }
                };
                self.shared = Some(shared);
                self.picture = (frame.width, frame.height);
                // SAFETY: GL calls on the current context.
                unsafe {
                    self.gl.use_program(Some(self.program));
                    self.gl.uniform_1_i32(self.mode.as_ref(), 2);
                }
                return Ok(());
            }
            #[cfg(not(all(windows, feature = "ffmpeg")))]
            match *picture {}
        }
        #[cfg(all(windows, feature = "ffmpeg"))]
        {
            self.shared = None;
        }
        let (w, h) = (frame.width, frame.height);
        let (cw, ch) = frame.chroma_size();
        // Plane, texture size, bytes per texel.
        let planes: Vec<(&[u8], u32, u32, u32)> = match frame.chroma {
            Chroma::Planar => vec![(&frame.y, w, h, 1), (&frame.u, cw, ch, 1), (&frame.v, cw, ch, 1)],
            Chroma::Interleaved => vec![(&frame.y, w, h, 1), (&frame.u, cw, ch, 2)],
        };
        let resize = self.picture != (w, h) || self.chroma != frame.chroma;
        // SAFETY: GL calls on the current context; each plane holds width × height texels.
        unsafe {
            for (unit, (texture, (data, pw, ph, texel))) in self.textures.iter().zip(planes).enumerate() {
                let len = (pw * ph * texel) as usize;
                if data.len() < len {
                    return Ok(());
                }
                let pixels = glow::PixelUnpackData::Slice(Some(&data[..len]));
                let (internal, format) = if texel == 2 { (glow::RG8, glow::RG) } else { (glow::R8, glow::RED) };
                self.gl.active_texture(glow::TEXTURE0 + unit as u32);
                self.gl.bind_texture(glow::TEXTURE_2D, Some(*texture));
                let (pw, ph) = (pw as i32, ph as i32);
                if resize {
                    let internal = internal as i32;
                    self.gl.tex_image_2d(glow::TEXTURE_2D, 0, internal, pw, ph, 0, format, glow::UNSIGNED_BYTE, pixels);
                } else {
                    self.gl.tex_sub_image_2d(glow::TEXTURE_2D, 0, 0, 0, pw, ph, format, glow::UNSIGNED_BYTE, pixels);
                }
            }
            self.gl.use_program(Some(self.program));
            let mode = if frame.chroma == Chroma::Interleaved { 1 } else { 0 };
            self.gl.uniform_1_i32(self.mode.as_ref(), mode);
        }
        self.picture = (w, h);
        self.chroma = frame.chroma;
        Ok(())
    }

    /// Draws the picture letterboxed into a `width` × `height` window and shows it. Returns
    /// where the picture landed, for mapping the pointer.
    pub fn draw(&mut self, width: u32, height: u32) -> Result<Viewport> {
        let (width, height) = (width.max(1), height.max(1));
        if self.drawable != (width, height) {
            self.surface.resize(&self.context, nonzero(width), nonzero(height));
            self.drawable = (width, height);
        }
        let (pw, ph) = self.picture;
        let vp = Viewport::fit(pw, ph, width, height);
        // SAFETY: GL calls on the current context, with this presenter's objects.
        unsafe {
            let gl = &self.gl;
            gl.viewport(0, 0, width as i32, height as i32);
            gl.clear_color(0.0, 0.0, 0.0, 1.0);
            gl.clear(glow::COLOR_BUFFER_BIT);
            if pw > 0 && ph > 0 {
                // GL counts rows from the bottom.
                let y = height - vp.y - vp.height;
                gl.viewport(vp.x as i32, y as i32, vp.width as i32, vp.height as i32);
                gl.use_program(Some(self.program));
                gl.bind_vertex_array(Some(self.vao));
                for (unit, texture) in self.textures.iter().enumerate() {
                    gl.active_texture(glow::TEXTURE0 + unit as u32);
                    gl.bind_texture(glow::TEXTURE_2D, Some(*texture));
                }
                #[cfg(all(windows, feature = "ffmpeg"))]
                if let (Some(shared), Some(interop)) = (self.shared, &self.interop) {
                    // The decoder's texture in place of the luma one, for this draw only.
                    interop.with(shared, || {
                        gl.active_texture(glow::TEXTURE0);
                        gl.bind_texture(glow::TEXTURE_2D, Some(shared.texture));
                        for (param, value) in [
                            (glow::TEXTURE_MIN_FILTER, glow::LINEAR),
                            (glow::TEXTURE_MAG_FILTER, glow::LINEAR),
                            (glow::TEXTURE_WRAP_S, glow::CLAMP_TO_EDGE),
                            (glow::TEXTURE_WRAP_T, glow::CLAMP_TO_EDGE),
                        ] {
                            gl.tex_parameter_i32(glow::TEXTURE_2D, param, value as i32);
                        }
                        gl.draw_arrays(glow::TRIANGLE_STRIP, 0, 4);
                    })?;
                    self.surface.swap_buffers(&self.context)?;
                    return Ok(vp);
                }
                gl.draw_arrays(glow::TRIANGLE_STRIP, 0, 4);
            }
        }
        self.surface.swap_buffers(&self.context)?;
        Ok(vp)
    }
}

impl Drop for Gpu {
    fn drop(&mut self) {
        #[cfg(all(windows, feature = "ffmpeg"))]
        if let Some(interop) = &mut self.interop {
            interop.release(&self.gl);
        }
        // SAFETY: the context is still current; these objects were created on it.
        unsafe {
            for texture in self.textures {
                self.gl.delete_texture(texture);
            }
            self.gl.delete_vertex_array(self.vao);
            self.gl.delete_program(self.program);
        }
    }
}

fn nonzero(n: u32) -> NonZeroU32 {
    NonZeroU32::new(n.max(1)).expect("at least 1")
}

/// Compiles and links the two stages, with the driver's log on failure.
///
/// # Safety
/// `gl` must be current on this thread.
unsafe fn link(gl: &glow::Context, vertex: &str, fragment: &str) -> Result<glow::Program> {
    // SAFETY: the caller guarantees a current context.
    unsafe {
        let program = gl.create_program().map_err(anyhow::Error::msg)?;
        let mut shaders = Vec::new();
        for (kind, source) in [(glow::VERTEX_SHADER, vertex), (glow::FRAGMENT_SHADER, fragment)] {
            let shader = gl.create_shader(kind).map_err(anyhow::Error::msg)?;
            gl.shader_source(shader, source);
            gl.compile_shader(shader);
            if !gl.get_shader_compile_status(shader) {
                anyhow::bail!("compiling a shader: {}", gl.get_shader_info_log(shader));
            }
            gl.attach_shader(program, shader);
            shaders.push(shader);
        }
        gl.link_program(program);
        if !gl.get_program_link_status(program) {
            anyhow::bail!("linking the shaders: {}", gl.get_program_info_log(program));
        }
        for shader in shaders {
            gl.detach_shader(program, shader);
            gl.delete_shader(shader);
        }
        Ok(program)
    }
}
