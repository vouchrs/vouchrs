//! Lazy string formatting utilities for performance optimization
//!
//! This module provides utilities for deferring string formatting operations until actually needed,
//! which can significantly reduce allocations when error messages are created but not displayed.

use std::fmt::{self, Display};

/// A lazy formatter that defers string formatting until actually used
pub struct LazyFormat<F>
where
    F: Fn() -> String,
{
    formatter: F,
}

impl<F> LazyFormat<F>
where
    F: Fn() -> String,
{
    /// Create a new lazy formatter
    pub fn new(formatter: F) -> Self {
        Self { formatter }
    }
}

impl<F> std::fmt::Debug for LazyFormat<F>
where
    F: Fn() -> String,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "LazyFormat {{ .. }}")
    }
}

impl<F> Display for LazyFormat<F>
where
    F: Fn() -> String,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", (self.formatter)())
    }
}

/// Macro for creating lazy formatted strings
#[macro_export]
macro_rules! lazy_format {
    ($($arg:tt)*) => {
        $crate::utils::lazy_format::LazyFormat::new(move || format!($($arg)*))
    };
}

/// Lazy error that formats only when displayed
pub struct LazyError<F>
where
    F: Fn() -> String,
{
    formatter: F,
}

impl<F> LazyError<F>
where
    F: Fn() -> String,
{
    /// Create a new lazy error
    pub fn new(formatter: F) -> Self {
        Self { formatter }
    }
}

impl<F> std::fmt::Debug for LazyError<F>
where
    F: Fn() -> String,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "LazyError {{ .. }}")
    }
}

impl<F> Display for LazyError<F>
where
    F: Fn() -> String,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", (self.formatter)())
    }
}

impl<F> std::error::Error for LazyError<F> where F: Fn() -> String {}

/// Macro for creating lazy errors
#[macro_export]
macro_rules! lazy_error {
    ($($arg:tt)*) => {
        $crate::utils::lazy_format::LazyError::new(move || format!($($arg)*))
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lazy_format() {
        let expensive_computation = || "expensive".to_string();
        let lazy = LazyFormat::new(move || format!("Result: {}", expensive_computation()));

        // Only formats when actually displayed
        assert_eq!(format!("{}", lazy), "Result: expensive");
    }

    #[test]
    fn test_lazy_format_macro() {
        let value = 42;
        let lazy = lazy_format!("Value: {}", value);
        assert_eq!(format!("{}", lazy), "Value: 42");
    }

    #[test]
    fn test_lazy_error() {
        let lazy_err = LazyError::new(|| "Something went wrong".to_string());
        assert_eq!(format!("{}", lazy_err), "Something went wrong");
    }

    #[test]
    fn test_lazy_error_macro() {
        let error_code = 404;
        let lazy_err = lazy_error!("Error {}: Not found", error_code);
        assert_eq!(format!("{}", lazy_err), "Error 404: Not found");
    }
}
