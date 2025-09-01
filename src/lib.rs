//! Wesolowski VDF Implementation
//!
//! This library provides a complete implementation of the Wesolowski Verifiable Delay Function (VDF)
//! using binary quadratic forms and class groups. The implementation includes:
//!
//! - Class group operations for binary quadratic forms
//! - Cryptographic utilities for discriminant generation and primality testing
//! - Complete VDF computation, proof generation, and verification
//!
//! # Example
//!
//! ```rust
//! use wesolowski_vdf::{WesolowskiVDF, ClassGroupElement};
//!
//! let vdf = WesolowskiVDF::new(b"challenge_string");
//! let (output, proof) = vdf.compute(10);
//! let is_valid = vdf.verify(&output, &proof, 10);
//! assert!(is_valid);
//! ```

pub mod class_group;
pub mod crypto;
pub mod vdf;

pub use class_group::ClassGroupElement;
pub use vdf::WesolowskiVDF;