//! Intrusive doubly-linked list
//!
//! "Intrusive" means the link pointers live INSIDE the data struct.
//! Used by: scheduler run queue, wait queues, LRU lists.
//!
//! This avoids allocation — the struct IS a list node.
//! Used heavily in Linux kernel as list_head.

// TODO: Implement ListNode { prev: *mut ListNode, next: *mut ListNode }
// TODO: Implement push_front, push_back, remove, iter
// NOTE: All operations are unsafe (raw pointer manipulation)
