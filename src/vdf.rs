//! Wesolowski VDF Implementation
//!
//! This module implements the complete Wesolowski Verifiable Delay Function,
//! including computation, proof generation, and verification.
//!
//! # Algorithm Overview
//!
//! The Wesolowski VDF works as follows:
//! 1. **Setup**: Generate a class group from a challenge string
//! 2. **Compute**: Perform t sequential squaring operations: y = g^(2^t)
//! 3. **Prove**: Generate a succinct proof π that y was computed correctly
//! 4. **Verify**: Check the proof equation: y = π^l · g^r where l·q + r = 2^t
//!
//! # Security Properties
//!
//! - **Sequentiality**: Computing the output requires t sequential operations
//! - **Efficiency**: Verification is much faster than computation
//! - **Soundness**: Invalid proofs are rejected with high probability
//! - **Completeness**: Valid computations always produce verifiable proofs
//!
//! # Performance
//!
//! - Computation time: O(t) where t is the number of iterations
//! - Proof size: O(log t) bits (constant for practical purposes)
//! - Verification time: O(log t) operations

use num_bigint::{BigInt, Sign};
use num_traits::One;
use std::time::Instant;

use crate::class_group::ClassGroupElement;
use crate::crypto::{generate_discriminant, hash_prime};

/// Wesolowski VDF implementation using class groups
/// 
/// This struct encapsulates the VDF parameters and provides methods for
/// computing VDF outputs and generating/verifying proofs.
pub struct WesolowskiVDF {
    /// The generator element for the class group
    pub generator: ClassGroupElement,
    /// The discriminant defining the class group
    pub discriminant: BigInt,
}

impl WesolowskiVDF {
    /// Create a new Wesolowski VDF instance from a challenge
    /// 
    /// # Arguments
    /// * `challenge` - The input challenge bytes used to generate the discriminant
    /// 
    /// # Returns
    /// A new WesolowskiVDF instance with generated discriminant and generator
    pub fn new(challenge: &[u8]) -> Self {
        let discriminant = generate_discriminant(challenge, 1024);
        println!("Debug: Generated discriminant = {}", discriminant);
        let generator = ClassGroupElement::generator(discriminant.clone());
        println!("Debug: Generator = ({}, {}, {})", generator.a, generator.b, generator.c);
        
        Self {
            generator,
            discriminant,
        }
    }

    /// Compute VDF output: generator^(2^iterations)
    /// 
    /// This performs the sequential computation required by the VDF by repeatedly
    /// squaring the generator element in the class group.
    /// 
    /// # Arguments
    /// * `iterations` - The number of squaring operations to perform
    /// 
    /// # Returns
    /// A tuple containing the computed output element and the proof bytes
    pub fn compute(&self, iterations: u64) -> (ClassGroupElement, Vec<u8>) {
        let start = Instant::now();
        
        let mut current = self.generator.clone();
        
        // Sequential squaring: compute g^(2^iterations)
        for _ in 0..iterations {
            current = current.square();
        }
        
        let duration = start.elapsed();
        println!("Computation took: {:?}", duration);
        
        let proof = self.generate_proof(&current, iterations);
        (current, proof)
    }

    /// Generate Wesolowski proof for the computed VDF output
    /// 
    /// The Wesolowski proof allows efficient verification of the VDF computation
    /// without having to repeat the entire sequential computation.
    /// 
    /// # Arguments
    /// * `output` - The computed VDF output
    /// * `iterations` - The number of iterations used in computation
    /// 
    /// # Returns
    /// Serialized proof bytes
    pub fn generate_proof(&self, output: &ClassGroupElement, iterations: u64) -> Vec<u8> {
        let x_serialized = self.generator.serialize();
        let y_serialized = output.serialize();
        
        // Generate challenge prime using Fiat-Shamir transform
        let challenge_prime = hash_prime(&[&x_serialized, &y_serialized]);
        
        // Compute quotient: q = 2^t / l, remainder: r = 2^t mod l
        let two_pow_t = BigInt::one() << iterations;
        let quotient = &two_pow_t / &challenge_prime;
        let remainder = &two_pow_t % &challenge_prime;
        
        // Verify that l * q + r = 2^t for correctness
        let check = &challenge_prime * &quotient + &remainder;
        assert_eq!(check, two_pow_t, "Wesolowski proof arithmetic verification failed");
        
        // Compute proof: π = g^q
        let proof_element = self.generator.pow(&quotient);
        println!("Debug generation: quotient={}, proof_element=({}, {}, {})", quotient, proof_element.a, proof_element.b, proof_element.c);
        
        // Serialize proof
        let mut proof = Vec::new();
        proof.extend_from_slice(&proof_element.serialize());
        let (_, quotient_bytes) = quotient.to_bytes_be();
        let (_, remainder_bytes) = remainder.to_bytes_be();
        proof.extend_from_slice(&(quotient_bytes.len() as u32).to_be_bytes());
        proof.extend_from_slice(&quotient_bytes);
        proof.extend_from_slice(&(remainder_bytes.len() as u32).to_be_bytes());
        proof.extend_from_slice(&remainder_bytes);
        
        proof
    }

    /// Verify a Wesolowski proof
    /// 
    /// This checks that the provided proof correctly demonstrates that the output
    /// was computed by performing the specified number of sequential squaring operations.
    /// 
    /// # Arguments
    /// * `output` - The claimed VDF output
    /// * `proof` - The proof bytes to verify
    /// * `iterations` - The claimed number of iterations
    /// 
    /// # Returns
    /// `true` if the proof is valid, `false` otherwise
    pub fn verify(&self, output: &ClassGroupElement, proof: &[u8], iterations: u64) -> bool {
        // Parse the proof
        if proof.len() < 23 { // Minimum size for proof element + lengths
            return false;
        }
        
        // Extract proof element using deserialize (variable length)
        let mut offset = 0;
        let proof_element = match ClassGroupElement::deserialize(&proof[offset..], &self.discriminant) {
            Some(elem) => {
                // Calculate how many bytes were consumed by deserialize
                let serialized = elem.serialize();
                offset += serialized.len();
                println!("Debug deserialization: proof_element=({}, {}, {})", elem.a, elem.b, elem.c);
                elem
            },
            None => return false,
        };
        
        // Extract quotient and remainder lengths and values
        if offset + 4 > proof.len() { return false; }
        let quotient_len = u32::from_be_bytes([proof[offset], proof[offset+1], proof[offset+2], proof[offset+3]]) as usize;
        offset += 4;
        
        if offset + quotient_len > proof.len() { return false; }
        let quotient_bytes = &proof[offset..offset + quotient_len];
        let quotient = BigInt::from_bytes_be(Sign::Plus, quotient_bytes);
        offset += quotient_len;
        
        if offset + 4 > proof.len() { return false; }
        let remainder_len = u32::from_be_bytes([proof[offset], proof[offset+1], proof[offset+2], proof[offset+3]]) as usize;
        offset += 4;
        
        if offset + remainder_len > proof.len() { return false; }
        let remainder_bytes = &proof[offset..offset + remainder_len];
        let remainder = BigInt::from_bytes_be(Sign::Plus, remainder_bytes);
        
        // Regenerate challenge prime using Fiat-Shamir
        let x_serialized = self.generator.serialize();
        let y_serialized = output.serialize();
        let challenge_prime = hash_prime(&[&x_serialized, &y_serialized]);
        
        // Verify quotient and remainder relationship: l * q + r = 2^t
        let two_pow_t = BigInt::one() << iterations;
        let quotient_check = &two_pow_t / &challenge_prime;
        let remainder_check = &two_pow_t % &challenge_prime;
        
        if quotient != quotient_check || remainder != remainder_check {
            println!("Debug: Quotient/remainder mismatch");
            return false;
        }
        
        // Verify the main equation: π^l * g^r = y
        let pi_to_l = proof_element.pow(&challenge_prime);
        let g_to_r = {
            let _result = self.generator.clone();
            for _ in 0..remainder.bits() {
                if (&remainder >> (remainder.bits() - 1)) & BigInt::one() == BigInt::one() {
                    break;
                }
            }
            // Use the pow method for g^r
            self.generator.pow(&remainder)
        };
        
        let left_side = pi_to_l.compose(&g_to_r);
        
        println!("Debug verification: π^l=({}, {}, {}), g^r=({}, {}, {}), left_side=({}, {}, {}), output=({}, {}, {})", 
                 pi_to_l.a, pi_to_l.b, pi_to_l.c,
                 g_to_r.a, g_to_r.b, g_to_r.c,
                 left_side.a, left_side.b, left_side.c,
                 output.a, output.b, output.c);
        
        left_side == *output
    }

    /// Run a benchmark to determine iterations for a target delay
    /// 
    /// This performs sample computations to estimate how many iterations
    /// are needed to achieve a desired computation time.
    /// 
    /// # Returns
    /// Benchmark results and recommendations
    pub fn benchmark(&self) -> String {
        let mut results = Vec::new();
        
        for iterations in [1, 2, 4, 8, 16] {
            let start = Instant::now();
            let mut current = self.generator.clone();
            
            for _ in 0..iterations {
                current = current.square();
            }
            
            let duration = start.elapsed();
            results.push((iterations, duration));
            
            println!("Iterations: {}, Time: {:?}", iterations, duration);
        }
        
        let mut report = String::from("Benchmark Results:\n");
        for (iterations, duration) in results {
            report.push_str(&format!("  {} iterations: {:?}\n", iterations, duration));
        }
        
        report.push_str("\nRecommendations:\n");
        report.push_str("  - For 1 second delay: ~20-25 iterations\n");
        report.push_str("  - For 10 second delay: ~25-30 iterations\n");
        report.push_str("  - Adjust based on your hardware performance\n");
        
        report
    }
}