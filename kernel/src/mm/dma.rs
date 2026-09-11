//! Physically contiguous, zeroed buffers for device DMA.

use super::{frame, order_for, phys_to_virt, PhysAddr, PAGE_SIZE};

pub struct DmaBuffer {
    phys: PhysAddr,
    order: usize,
}

impl DmaBuffer {
    pub fn new(bytes: usize) -> Option<Self> {
        let order = order_for(bytes);
        let phys = frame::alloc_zeroed(order)?;
        Some(Self { phys, order })
    }
    pub fn phys(&self) -> PhysAddr {
        self.phys
    }
    pub fn len(&self) -> usize {
        PAGE_SIZE << self.order
    }
    pub fn as_ptr(&self) -> *mut u8 {
        phys_to_virt(self.phys) as *mut u8
    }
    pub fn as_slice(&self) -> &[u8] {
        unsafe { core::slice::from_raw_parts(self.as_ptr(), self.len()) }
    }
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        unsafe { core::slice::from_raw_parts_mut(self.as_ptr(), self.len()) }
    }
}

impl Drop for DmaBuffer {
    fn drop(&mut self) {
        frame::free(self.phys, self.order);
    }
}

// Device memory is referenced by physical address only; moving the handle
// between tasks is fine.
unsafe impl Send for DmaBuffer {}
unsafe impl Sync for DmaBuffer {}
