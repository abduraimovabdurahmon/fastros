//! Round-Robin run queue
//!
//! Static circular queue of process indices (into PROCESS_TABLE).
//! On each tick: move current process to back, pick next from front.
//!
//! This is cooperative + preemptive:
//!   - Cooperative: a process can yield() to immediately trigger a switch.
//!   - Preemptive:  the timer tick advances the queue every 10 ms.

use crate::kernel::process::process::ProcessState;

const QUEUE_SIZE: usize = 64;

static mut QUEUE: [usize; QUEUE_SIZE] = [0; QUEUE_SIZE];
static mut HEAD:  usize = 0; // index of first element
static mut TAIL:  usize = 0; // index of next free slot
static mut LEN:   usize = 0;

/// Index into PROCESS_TABLE of the currently running process.
/// usize::MAX = no process running (idle).
pub static mut CURRENT_IDX: usize = usize::MAX;

/// Push a process index onto the back of the run queue.
pub fn enqueue(idx: usize) {
    unsafe {
        if LEN >= QUEUE_SIZE { return; } // queue full — drop (shouldn't happen)
        QUEUE[TAIL] = idx;
        TAIL = (TAIL + 1) % QUEUE_SIZE;
        LEN += 1;
    }
}

/// Pop the front process index from the run queue.
pub fn dequeue() -> Option<usize> {
    unsafe {
        if LEN == 0 { return None; }
        let idx = QUEUE[HEAD];
        HEAD = (HEAD + 1) % QUEUE_SIZE;
        LEN -= 1;
        Some(idx)
    }
}

/// Remove a specific process index from the queue (for block/exit).
pub fn remove(target_idx: usize) {
    unsafe {
        // Rebuild the queue without `target_idx`
        let mut tmp = [0usize; QUEUE_SIZE];
        let mut new_len = 0usize;
        for i in 0..LEN {
            let idx = QUEUE[(HEAD + i) % QUEUE_SIZE];
            if idx != target_idx {
                tmp[new_len] = idx;
                new_len += 1;
            }
        }
        for i in 0..new_len {
            QUEUE[i] = tmp[i];
        }
        HEAD = 0;
        TAIL = new_len % QUEUE_SIZE;
        LEN  = new_len;
    }
}

pub fn queue_len() -> usize { unsafe { LEN } }
pub fn current()   -> usize { unsafe { CURRENT_IDX } }
