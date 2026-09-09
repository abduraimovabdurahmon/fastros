//! Linear Framebuffer Driver (VESA / UEFI GOP)
//!
//! Pixel-based display. Bootloader provides:
//!   - Physical address of framebuffer
//!   - Width, height, pitch (bytes per row)
//!   - Pixel format (usually 32-bit BGRA or RGBX)
//!
//! Enables graphics, custom fonts (PSF), and GUI in the future.

// TODO: Parse framebuffer info from Multiboot2 framebuffer tag.
// TODO: Implement put_pixel(x, y, color: u32).
// TODO: Implement blit(dst_x, dst_y, src: &[u8], w, h) for images/fonts.
