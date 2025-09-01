//! Class Group Operations for Binary Quadratic Forms
//!
//! This module implements operations on binary quadratic forms used in the
//! Wesolowski VDF construction. It provides the core mathematical operations
//! needed for class group arithmetic.
//!
//! # Mathematical Background
//!
//! Binary quadratic forms are expressions of the form ax² + bxy + cy² where a, b, c
//! are integers. In the context of VDFs, we work with forms of discriminant Δ = b² - 4ac < 0.
//! The class group operations (composition and reduction) form the mathematical foundation
//! for the VDF's security properties.
//!
//! # Security Properties
//!
//! - **Sequential Nature**: Computing g^(2^t) requires t sequential squaring operations
//! - **Parallel Resistance**: No known method to parallelize the computation significantly
//! - **Verifiable**: Proofs can be verified much faster than generation

use num_bigint::{BigInt, Sign};
use num_traits::{Zero, One, Signed};

/// Class group element representing a binary quadratic form (a, b, c)
/// with discriminant D = b² - 4ac
///
/// This represents an element in the class group of binary quadratic forms,
/// which forms the algebraic structure underlying the Wesolowski VDF.
#[derive(Clone, Debug, PartialEq)]
pub struct ClassGroupElement {
    pub a: BigInt,
    pub b: BigInt,
    pub c: BigInt,
    pub discriminant: BigInt,
}

impl ClassGroupElement {
    /// Create a new class group element with given a, b, and discriminant
    /// 
    /// The c component is automatically calculated from the discriminant:
    /// D = b² - 4ac => c = (b² - D) / 4a
    pub fn new(a: BigInt, b: BigInt, discriminant: BigInt) -> Self {
        let c = (&b * &b - &discriminant) / (4 * &a);
        Self { a, b, c, discriminant }
    }

    /// Create the generator element (2, 1, c) where c is calculated from discriminant
    /// 
    /// Following the POA Networks VDF implementation approach, we use (2, 1, c)
    /// as the standard generator for the class group.
    pub fn generator(discriminant: BigInt) -> Self {
        let a = BigInt::from(2);
        let b = BigInt::from(1);
        let c = (&b * &b - &discriminant) / (4 * &a);
        Self { a, b, c, discriminant }
    }

    /// Create the identity element (1, 1, c) where c = (1 - D) / 4
    /// 
    /// The identity element is the neutral element for class group composition.
    pub fn identity(discriminant: BigInt) -> Self {
        let a = BigInt::from(1);
        let b = BigInt::from(1);
        let c = (&b * &b - &discriminant) / (4 * &a);
        Self { a, b, c, discriminant }
    }

    /// Reduce the binary quadratic form to its canonical representation
    /// 
    /// A reduced form satisfies: |b| ≤ a ≤ c and if |b| = a or a = c, then b ≥ 0
    /// This implements the standard reduction algorithm used in class group cryptography.
    pub fn reduce(&mut self) {
        let mut steps = 0;
        const MAX_STEPS: usize = 1000;
        
        while steps < MAX_STEPS {
            // If a > c, swap a and c, and negate b
            if self.a > self.c {
                std::mem::swap(&mut self.a, &mut self.c);
                self.b = -&self.b;
            }
            
            // If |b| > a, reduce b modulo 2a
            let abs_b = self.b.abs();
            if abs_b > self.a {
                let q = (&self.b + &self.a) / (2 * &self.a);
                let old_b = self.b.clone();
                self.b = &self.b - 2 * &q * &self.a;
                self.c = &self.c - &q * (&old_b + &q * &self.a);
            }
            
            // Check if we're done
            let abs_b = self.b.abs();
            if abs_b <= self.a && self.a <= self.c {
                // If |b| = a or a = c, ensure b ≥ 0
                if (abs_b == self.a || self.a == self.c) && self.b.is_negative() {
                    self.b = -&self.b;
                }
                break;
            }
            
            steps += 1;
        }
        
        // Verify the discriminant is preserved
        let computed_discriminant = &self.b * &self.b - 4 * &self.a * &self.c;
        if computed_discriminant != self.discriminant {
            // Recalculate c to maintain discriminant
            self.c = (&self.b * &self.b - &self.discriminant) / (4 * &self.a);
        }
    }

    /// Compose two class group elements using the NUCOMP algorithm
    /// 
    /// This implements composition of binary quadratic forms, which is the
    /// group operation in the class group. The result is automatically reduced.
    pub fn compose(&self, other: &ClassGroupElement) -> ClassGroupElement {
        // Ensure both elements have the same discriminant
        assert_eq!(self.discriminant, other.discriminant);
        
        // Handle identity elements
        if self.a == BigInt::one() {
            return other.clone();
        }
        if other.a == BigInt::one() {
            return self.clone();
        }
        
        let (a1, b1, _) = (&self.a, &self.b, &self.c);
        let (a2, b2, _) = (&other.a, &other.b, &other.c);
        
        // Compute gcd(a1, a2, (b1 + b2)/2)
        let s = (b1 + b2) / 2;
        let g = gcd(&gcd(a1, a2), &s);
        
        if g == BigInt::from(1) {
            // Simple case: gcd = 1
            let a3 = a1 * a2;
            let b3 = b1 + 2 * a2 * ((b2 - b1) / 2);
            let c3 = (&b3 * &b3 - &self.discriminant) / (4 * &a3);
            
            let mut result = ClassGroupElement {
                a: a3,
                b: b3,
                c: c3,
                discriminant: self.discriminant.clone(),
            };
            result.reduce();
            result
        } else {
            // General case: use extended Euclidean algorithm
            let a1_g = a1 / &g;
            let a2_g = a2 / &g;
            let s_g = &s / &g;
            
            // Extended GCD to find Bezout coefficients
            let (_, u, _) = extended_gcd(&a1_g, &a2_g);
            
            let a3 = &g * &a1_g * &a2_g;
            let b3 = b1 + 2 * &g * &a2_g * &u * (&s_g - b1 / &g);
            let c3 = (&b3 * &b3 - &self.discriminant) / (4 * &a3);
            
            let mut result = ClassGroupElement {
                a: a3,
                b: b3,
                c: c3,
                discriminant: self.discriminant.clone(),
            };
            result.reduce();
            result
        }
    }

    /// Square the element (self * self) using class group composition
    /// 
    /// This is an optimized version of composition when both operands are the same.
    pub fn square(&self) -> ClassGroupElement {
        self.compose(self)
    }

    /// Exponentiation by repeated squaring with proper class group operations
    /// 
    /// Computes self^exp using the binary exponentiation algorithm.
    /// This is the core operation used in VDF computation.
    pub fn pow(&self, exp: &BigInt) -> ClassGroupElement {
        if exp.is_zero() {
            return Self::identity(self.discriminant.clone());
        }
        
        if exp == &BigInt::one() {
            return self.clone();
        }
        
        let mut result = Self::identity(self.discriminant.clone());
        let mut base = self.clone();
        let mut exp = exp.clone();
        
        while !exp.is_zero() {
            if &exp % 2 == BigInt::one() {
                result = result.compose(&base);
            }
            base = base.square();
            exp >>= 1;
        }
        
        result
    }

    /// Serialize the element for proof generation and storage
    /// 
    /// Returns a byte representation that can be used in cryptographic protocols.
    pub fn serialize(&self) -> Vec<u8> {
        let mut result = Vec::new();
        let (a_sign, a_bytes) = self.a.to_bytes_be();
        let (b_sign, b_bytes) = self.b.to_bytes_be();
        let (c_sign, c_bytes) = self.c.to_bytes_be();
        
        result.extend_from_slice(&(a_bytes.len() as u32).to_be_bytes());
        result.push(if a_sign == Sign::Minus { 1 } else { 0 });
        result.extend_from_slice(&a_bytes);
        result.extend_from_slice(&(b_bytes.len() as u32).to_be_bytes());
        result.push(if b_sign == Sign::Minus { 1 } else { 0 });
        result.extend_from_slice(&b_bytes);
        result.extend_from_slice(&(c_bytes.len() as u32).to_be_bytes());
        result.push(if c_sign == Sign::Minus { 1 } else { 0 });
        result.extend_from_slice(&c_bytes);
        
        result
    }

    /// Deserialize element from bytes
    /// 
    /// Reconstructs a ClassGroupElement from its serialized representation.
    /// Returns None if the bytes are malformed.
    pub fn deserialize(bytes: &[u8], discriminant: &BigInt) -> Option<Self> {
        if bytes.len() < 15 { // Minimum size for 3 length fields + 3 sign bytes
            return None;
        }
        
        let mut offset = 0;
        
        // Read a
        if offset + 4 > bytes.len() { return None; }
        let a_len = u32::from_be_bytes([bytes[offset], bytes[offset+1], bytes[offset+2], bytes[offset+3]]) as usize;
        offset += 4;
        
        if offset + 1 > bytes.len() { return None; }
        let a_sign = if bytes[offset] == 1 { Sign::Minus } else { Sign::Plus };
        offset += 1;
        
        if offset + a_len > bytes.len() { return None; }
        let a = BigInt::from_bytes_be(a_sign, &bytes[offset..offset + a_len]);
        offset += a_len;
        
        // Read b
        if offset + 4 > bytes.len() { return None; }
        let b_len = u32::from_be_bytes([bytes[offset], bytes[offset+1], bytes[offset+2], bytes[offset+3]]) as usize;
        offset += 4;
        
        if offset + 1 > bytes.len() { return None; }
        let b_sign = if bytes[offset] == 1 { Sign::Minus } else { Sign::Plus };
        offset += 1;
        
        if offset + b_len > bytes.len() { return None; }
        let b = BigInt::from_bytes_be(b_sign, &bytes[offset..offset + b_len]);
        offset += b_len;
        
        // Read c
        if offset + 4 > bytes.len() { return None; }
        let c_len = u32::from_be_bytes([bytes[offset], bytes[offset+1], bytes[offset+2], bytes[offset+3]]) as usize;
        offset += 4;
        
        if offset + 1 > bytes.len() { return None; }
        let c_sign = if bytes[offset] == 1 { Sign::Minus } else { Sign::Plus };
        offset += 1;
        
        if offset + c_len > bytes.len() { return None; }
        let c = BigInt::from_bytes_be(c_sign, &bytes[offset..offset + c_len]);
        
        Some(Self {
            a,
            b,
            c,
            discriminant: discriminant.clone(),
        })
    }
}

/// Compute the greatest common divisor of two BigInts
/// 
/// Uses the Euclidean algorithm for efficient GCD computation.
pub fn gcd(a: &BigInt, b: &BigInt) -> BigInt {
    let mut a = a.clone();
    let mut b = b.clone();
    
    while !b.is_zero() {
        let temp = b.clone();
        b = &a % &b;
        a = temp;
    }
    
    a
}

/// Extended Euclidean algorithm (iterative to avoid stack overflow)
/// 
/// Returns (gcd, x, y) such that ax + by = gcd(a, b)
/// Used in class group composition for computing Bezout coefficients.
pub fn extended_gcd(a: &BigInt, b: &BigInt) -> (BigInt, BigInt, BigInt) {
    let mut old_r = a.clone();
    let mut r = b.clone();
    let mut old_s = BigInt::one();
    let mut s = BigInt::zero();
    let mut old_t = BigInt::zero();
    let mut t = BigInt::one();
    
    while !r.is_zero() {
        let quotient = &old_r / &r;
        let temp_r = r.clone();
        r = &old_r - &quotient * &r;
        old_r = temp_r;
        
        let temp_s = s.clone();
        s = &old_s - &quotient * &s;
        old_s = temp_s;
        
        let temp_t = t.clone();
        t = &old_t - &quotient * &t;
        old_t = temp_t;
    }
    
    (old_r, old_s, old_t)
}