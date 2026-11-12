// SPDX-License-Identifier: GPL-2.0-or-later

//! Minimal logging to standard error

use std::sync::atomic::{AtomicBool, Ordering};

static DEBUG: AtomicBool = AtomicBool::new(false);

pub fn set_debug(on: bool) {
    DEBUG.store(on, Ordering::Relaxed);
}

pub fn debug_enabled() -> bool {
    DEBUG.load(Ordering::Relaxed)
}

/// Log a message only if debugging output was requested
macro_rules! debug {
    ($($arg:tt)*) => {
        if $crate::log::debug_enabled() {
            eprintln!("specchio: {}", format_args!($($arg)*));
        }
    };
}

/// Log a message unconditionally
macro_rules! info {
    ($($arg:tt)*) => {
        eprintln!("specchio: {}", format_args!($($arg)*))
    };
}

pub(crate) use {debug, info};
