//! Cryptographic Utilities for VDF Implementation
//!
//! This module provides cryptographic functions needed for the Wesolowski VDF,
//! including discriminant generation, hashing, and primality testing.
//!
//! # Key Functions
//!
//! - **Discriminant Generation**: Creates cryptographically secure negative discriminants
//!   that satisfy the mathematical requirements for class group operations
//! - **Prime Generation**: Uses Fiat-Shamir heuristic to generate challenge primes
//!   for the non-interactive proof system
//! - **Primality Testing**: Miller-Rabin probabilistic primality test for efficiency
//!
//! # Security Considerations
//!
//! - Discriminants must be ≡ 1 (mod 4) for proper class group structure
//! - Challenge primes are generated deterministically from public inputs
//! - All randomness is derived from cryptographic hash functions

use num_bigint::{BigInt, Sign};
use num_traits::{Zero, One, Signed};
use sha2::{Sha256, Digest};

/// Generate a cryptographically secure discriminant from challenge
/// 
/// Following the approach used in POA Networks VDF implementation,
/// this generates a negative discriminant of specified bit length that
/// satisfies the requirement D ≡ 1 (mod 4) for proper class group structure.
/// 
/// # Arguments
/// * `challenge` - The input challenge bytes
/// * `bit_length` - Desired bit length of the discriminant
/// 
/// # Returns
/// A negative BigInt discriminant suitable for class group operations
pub fn generate_discriminant(challenge: &[u8], bit_length: usize) -> BigInt {
    let mut hasher = Sha256::new();
    hasher.update(challenge);
    hasher.update(b"wesolowski_discriminant");
    
    let mut discriminant;
    let mut counter = 0u64;
    
    // Generate a negative discriminant of specified bit length
    // Must be ≡ 1 (mod 4) for proper class group structure
    loop {
        let mut hasher = Sha256::new();
        hasher.update(challenge);
        hasher.update(b"discriminant_generation");
        hasher.update(counter.to_be_bytes());
        let hash = hasher.finalize();
        
        // Create discriminant from hash
        discriminant = BigInt::from_bytes_be(Sign::Plus, &hash);
        
        // Ensure proper bit length by setting the most significant bit
        if bit_length > 256 {
            // For larger bit lengths, extend with additional hashing
            let mut extended_bytes = Vec::new();
            let mut hash_counter = 0u32;
            
            while extended_bytes.len() * 8 < bit_length {
                let mut ext_hasher = Sha256::new();
                ext_hasher.update(hash);
                ext_hasher.update(hash_counter.to_be_bytes());
                let ext_hash = ext_hasher.finalize();
                extended_bytes.extend_from_slice(&ext_hash);
                hash_counter += 1;
            }
            
            // Truncate to desired bit length
            let byte_length = bit_length.div_ceil(8);
            extended_bytes.truncate(byte_length);
            discriminant = BigInt::from_bytes_be(Sign::Plus, &extended_bytes);
        }
        
        // Set the discriminant to be negative
        discriminant = -discriminant.abs();
        
        // Ensure discriminant ≡ 1 (mod 4) for proper class group
        let remainder = &discriminant % 4;
        if remainder != BigInt::from(-3) {
            discriminant -= &remainder + 3;
        }
        
        // Check if discriminant has the correct bit length
        let actual_bits = discriminant.bits() as usize;
        if actual_bits >= bit_length - 8 && actual_bits <= bit_length + 8 {
            break;
        }
        
        counter += 1;
        if counter > 10000 {
            // Fallback discriminant with correct properties
            discriminant = -(BigInt::one() << (bit_length - 1)) - BigInt::from(3);
            // Ensure ≡ 1 (mod 4)
            let remainder = &discriminant % 4;
            if remainder != BigInt::from(-3) {
                discriminant -= &remainder + 3;
            }
            break;
        }
    }
    
    discriminant
}

/// Hash function to generate prime for Fiat-Shamir transform
/// 
/// This function takes multiple byte arrays and produces a prime number
/// using SHA-256 hashing followed by primality testing.
/// 
/// # Arguments
/// * `data` - Array of byte slices to hash together
/// 
/// # Returns
/// A prime BigInt suitable for cryptographic use
pub fn hash_prime(data: &[&[u8]]) -> BigInt {
    let mut hasher = Sha256::new();
    for d in data {
        hasher.update(d);
    }
    let hash = hasher.finalize();
    
    let mut prime = BigInt::from_bytes_be(Sign::Plus, &hash);
    
    // Ensure it's odd
    if &prime % 2 == BigInt::zero() {
        prime += 1;
    }
    
    // Simple primality check (for demo purposes)
    while !is_probably_prime(&prime) {
        prime += 2;
    }
    
    prime
}

/// Simple Miller-Rabin primality test
/// 
/// This implements a probabilistic primality test using the Miller-Rabin algorithm
/// with a fixed set of small witnesses. For cryptographic applications, this should
/// be replaced with a more robust implementation.
/// 
/// # Arguments
/// * `n` - The number to test for primality
/// 
/// # Returns
/// `true` if the number is probably prime, `false` if it's definitely composite
pub fn is_probably_prime(n: &BigInt) -> bool {
    if n < &BigInt::from(2) {
        return false;
    }
    if n == &BigInt::from(2) || n == &BigInt::from(3) {
        return true;
    }
    if n % 2 == BigInt::zero() {
        return false;
    }
    
    // Miller-Rabin with a few small witnesses
    let witnesses = [2, 3, 5, 7, 11, 13, 17, 19, 23];
    
    for &a in &witnesses {
        if n <= &BigInt::from(a) {
            return n == &BigInt::from(a);
        }
        
        let n_minus_1: BigInt = n - 1;
        let mut d = n_minus_1.clone();
        let mut r = 0;
        
        while &d % 2 == BigInt::zero() {
            d >>= 1;
            r += 1;
        }
        
        let mut x = mod_pow(&BigInt::from(a), &d, n);
        
        if x == BigInt::one() || x == n_minus_1 {
            continue;
        }
        
        let mut composite = true;
        for _ in 0..r-1 {
            x = mod_pow(&x, &BigInt::from(2), n);
            if x == n_minus_1 {
                composite = false;
                break;
            }
        }
        
        if composite {
            return false;
        }
    }
    
    true
}

/// Modular exponentiation using binary exponentiation
/// 
/// Computes (base^exp) mod modulus efficiently using the square-and-multiply algorithm.
/// 
/// # Arguments
/// * `base` - The base number
/// * `exp` - The exponent
/// * `modulus` - The modulus
/// 
/// # Returns
/// The result of (base^exp) mod modulus
pub fn mod_pow(base: &BigInt, exp: &BigInt, modulus: &BigInt) -> BigInt {
    if exp.is_zero() {
        return BigInt::one();
    }
    
    let mut result = BigInt::one();
    let mut base = base % modulus;
    let mut exp = exp.clone();
    
    while !exp.is_zero() {
        if &exp % 2 == BigInt::one() {
            result = (result * &base) % modulus;
        }
        base = (&base * &base) % modulus;
        exp >>= 1;
    }
    
    result
}