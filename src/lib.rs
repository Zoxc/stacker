//! A library to help grow the stack when it runs out of space.
//!
//! This is an implementation of manually instrumented segmented stacks where
//! points in a program's control flow are annotated with "maybe grow the stack
//! here". Each point of annotation indicates how far away from the end of the
//! stack it's allowed to be, plus the amount of stack to allocate if it does
//! reach the end.
//!
//! Once a program has reached the end of its stack, a temporary stack on the
//! heap is allocated and is switched to for the duration of a closure.
//!
//! # Examples
//!
//! ```
//! // Grow the stack if we are within the "red zone" of 32K, and if we allocate
//! // a new stack allocate 1MB of stack space.
//! //
//! // If we're already in bounds, however, just run the provided closure on our
//! // own stack
//! stacker::maybe_grow(32 * 1024, 1024 * 1024, || {
//!     // guaranteed to have at least 32K of stack
//! });
//! ```

#![allow(improper_ctypes)]

#[macro_use]
extern crate cfg_if;
extern crate libc;
#[cfg(windows)]
extern crate kernel32;
#[cfg(windows)]
extern crate winapi;

/// Grows the call stack if necessary.
///
/// This function is intended to be called at manually instrumented points in a
/// program where recursion is known to happen quite a bit. This function will
/// check to see if we're within `red_zone` bytes of the end of the stack, and
/// if so it will allocate a new stack of size `stack_size`.
///
/// The closure `f` is guaranteed to run on a stack with at least `red_zone`
/// bytes, and it will be run on the current stack if there's space available.
#[inline(always)]
pub fn maybe_grow<R, F: FnOnce() -> R>(red_zone: usize,
                                       stack_size: usize,
                                       f: F) -> R {
    if remaining_stack() >= red_zone {
        f()
    } else {
        grow_the_stack(stack_size, f)
    }
}

/// Queries the amount of remaining stack as interpreted by this library.
///
/// This function will return the amount of stack space left which will be used
/// to determine whether a stack switch should be made or not.
#[inline(always)]
pub fn remaining_stack() -> usize {
    &mut () as *mut _ as usize - get_stack_limit()
}

#[inline(never)]
fn grow_the_stack<R, F: FnOnce() -> R>(stack_size: usize, f: F) -> R {
    let mut f = Some(f);
    let mut ret = None;
    _grow_the_stack(stack_size, &mut || {
        ret = Some(f.take().unwrap()());
    });
    ret.unwrap()
}

cfg_if! {
    if #[cfg(not(windows))] {
        use std::cell::Cell;

        extern {
            fn __stacker_switch_stacks(new_stack_high: usize,
                                    new_stack_low: usize,
                                    fnptr: *const u8,
                                    dataptr: *mut u8,
                                    stack_committed: usize);
        }

        thread_local! {
            static STACK_LIMIT: Cell<usize> = Cell::new(unsafe {
                guess_os_stack_limit()
            })
        }

        #[inline(always)]
        fn get_stack_limit() -> usize {
            STACK_LIMIT.with(|s| s.get())
        }

        fn set_stack_limit(l: usize) {
            STACK_LIMIT.with(|s| s.set(l))
        }

        unsafe fn _grow_the_stack(stack_size: usize, mut f: &mut FnMut()) {
            // Align to 16-bytes (see below for why)
            let stack_size = (stack_size + 15) / 16 * 16;

            // Allocate some new stack for oureslves
            let mut stack = Vec::<u8>::with_capacity(stack_size);
            let new_limit = stack.as_ptr() as usize + 32 * 1024;

            // Save off the old stack limits
            let old_limit = get_stack_limit();

            // Prepare stack limits for the stack switch
            set_stack_limit(new_limit);

            // Make sure the stack is 16-byte aligned which should be enough for all
            // platforms right now. Allocations on 64-bit are already 16-byte aligned
            // and our switching routine doesn't push any other data, but the routine on
            // 32-bit pushes an argument so we need a bit of an offset to get it 16-byte
            // aligned when the call is made.
            let offset = if cfg!(target_pointer_width = "32") {
                12
            } else {
                0
            };
            __stacker_switch_stacks(stack.as_mut_ptr() as usize + stack_size - offset,
                                    doit as usize as *const _,
                                    &mut f as *mut &mut FnMut() as *mut u8);

            // Once we've returned reset bothe stack limits and then return value same
            // value the closure returned.
            set_stack_limit(old_limit);
        }
    }
}

extern fn doit(f: &mut &mut FnMut()) {
    f();
}

cfg_if! {
    if #[cfg(windows)] {
        extern {
            fn __stacker_switch_stacks(stack_size: usize, callback: usize, data: *mut u8) -> winapi::BOOL;
        }

        #[no_mangle]
        pub unsafe extern fn __stacker_switch_stacks_callback(f: &mut &mut FnMut()) {
            f();
        }

        fn _grow_the_stack(stack_size: usize, mut f: &mut FnMut()) {
            unsafe {
                println!("dfgdg");
                if __stacker_switch_stacks(stack_size, doit as usize, &mut f as *mut _ as *mut u8) == winapi::FALSE {
                    panic!("unable to grow the stack")
                }
            }
        }

        cfg_if! {
            if #[cfg(any(target_arch = "x86_64", target_arch = "x86"))] {
                extern {
                    fn __stacker_get_stack_limit() -> usize;
                }

                #[inline(always)]
                fn get_stack_limit() -> usize {
                    unsafe {
                        __stacker_get_stack_limit()
                    }
                }
            } else {
                #[inline(always)]
                fn get_thread_stack_guarantee() -> usize {
                    let min_guarantee = if cfg!(target_pointer_width = "32") {
                        0x1000
                    } else {
                        0x2000
                    };
                    let mut stack_guarantee = 0;
                    unsafe {
                        kernel32::SetThreadStackGuarantee(&mut stack_guarantee)
                    };
                    std::cmp::max(stack_guarantee, min_guarantee) as usize + 0x1000
                }

                #[inline(always)]
                fn get_stack_limit() -> usize {
                    let mut mi;
                    unsafe {
                        kernel32::VirtualQuery(&mut () as *mut (), &mut mi, std::mem::size_of_val(&mi));
                    }
                    mi.AllocationBase + get_thread_stack_guarantee() + 0x1000
                }
            }
        }
    } else if #[cfg(target_os = "linux")] {
        use std::mem;

        unsafe fn guess_os_stack_limit() -> usize {
            let mut attr: libc::pthread_attr_t = mem::zeroed();
            assert_eq!(libc::pthread_attr_init(&mut attr), 0);
            assert_eq!(libc::pthread_getattr_np(libc::pthread_self(),
                                                &mut attr), 0);
            let mut stackaddr = 0 as *mut _;
            let mut stacksize = 0;
            assert_eq!(libc::pthread_attr_getstack(&attr, &mut stackaddr,
                                                   &mut stacksize), 0);
            assert_eq!(libc::pthread_attr_destroy(&mut attr), 0);
            stackaddr as usize
        }
    } else if #[cfg(target_os = "macos")] {
        use libc::{c_void, pthread_t, size_t};

        unsafe fn guess_os_stack_limit() -> usize {
            libc::pthread_get_stackaddr_np(libc::pthread_self()) as usize -
                libc::pthread_get_stacksize_np(libc::pthread_self()) as usize
        }
    } else {
        unsafe fn guess_os_stack_limit() -> usize {
            panic!("cannot guess the stack limit on this platform");
        }
    }
}
