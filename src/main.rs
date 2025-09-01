//! Wesolowski VDF CLI Application
//!
//! A command-line interface for the Wesolowski Verifiable Delay Function (VDF)
//! implementation using class groups of binary quadratic forms.

use clap::{Parser, Subcommand};
use std::time::Duration;

mod class_group;
mod crypto;
mod vdf;

use class_group::ClassGroupElement;
use vdf::WesolowskiVDF;

#[derive(Parser)]
#[command(name = "wesolowski_vdf")]
#[command(about = "A Real Wesolowski VDF implementation using class groups")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Compute VDF proof
    Compute {
        /// Challenge input (hex string)
        challenge: String,
        /// Number of iterations (difficulty)
        iterations: u64,
    },
    /// Verify VDF proof
    Verify {
        /// Challenge input (hex string)
        challenge: String,
        /// Number of iterations (difficulty)
        iterations: u64,
        /// Proof to verify (hex string)
        proof: String,
        /// Output a component (optional, will recompute if not provided)
        #[arg(long)]
        output_a: Option<String>,
        /// Output b component (optional, will recompute if not provided)
        #[arg(long)]
        output_b: Option<String>,
        /// Output c component (optional, will recompute if not provided)
        #[arg(long)]
        output_c: Option<String>,
    },
    /// Benchmark to find iterations for target delay
    Benchmark,
}



use std::time::Instant;
use num_bigint::BigInt;

/// Benchmark function to determine optimal iterations for timing
/// 
/// Runs VDF computations with different iteration counts to find
/// the optimal number for a 100ms-1000ms delay range.
fn benchmark_iterations() -> u64 {
    println!("Benchmarking to find iterations for 100ms minimum delay...");
    
    let challenge = b"benchmark_challenge";
    let vdf = WesolowskiVDF::new(challenge);
    
    let target_min = Duration::from_millis(100);
    let target_max = Duration::from_millis(1000);
    
    // Test with higher iteration counts to reach 100ms-1000ms target range
    let test_iterations = [10, 15, 20, 25, 30, 40, 50, 75, 100, 150, 200, 300, 500];
    
    for &test_iter in &test_iterations {
        let start = Instant::now();
        let _ = vdf.compute(test_iter);
        let duration = start.elapsed();
        
        println!("Iterations: {}, Duration: {:?}", test_iter, duration);
        
        if duration >= target_min && duration <= target_max {
            println!("Found target iterations: {} for duration: {:?}", test_iter, duration);
            return test_iter;
        }
        
        if duration > target_max {
            // Interpolate
            if test_iter > 10 {
                let ratio = target_min.as_millis() as f64 / duration.as_millis() as f64;
                let estimated = ((test_iter as f64 * ratio) as u64).max(1);
                println!("Estimated iterations for target: {}", estimated);
                
                let start = Instant::now();
                let _ = vdf.compute(estimated);
                let duration = start.elapsed();
                println!("Estimated test - Iterations: {}, Duration: {:?}", estimated, duration);
                
                if duration >= target_min && duration <= target_max {
                    return estimated;
                }
            }
            break;
        }
    }
    
    println!("Using fallback iterations: 10");
    10
}

/// Main function - entry point for the CLI application
/// 
/// Parses command line arguments and dispatches to appropriate VDF operations.
fn main() {
    let cli = Cli::parse();
    
    match cli.command {
        Commands::Compute { challenge, iterations } => {
            let challenge_bytes = hex::decode(&challenge).unwrap_or_else(|_| challenge.into_bytes());
            let vdf = WesolowskiVDF::new(&challenge_bytes);
            
            println!("Computing Real Wesolowski VDF with {} iterations...", iterations);
            let (output, proof) = vdf.compute(iterations);
            
            println!("Output a: {}", output.a);
            println!("Output b: {}", output.b);
            println!("Output c: {}", output.c);
            println!("Proof: {}", hex::encode(&proof));
        }
        
        Commands::Verify { challenge, iterations, proof, output_a, output_b, output_c } => {
            let challenge_bytes = hex::decode(&challenge).unwrap_or_else(|_| challenge.into_bytes());
            let proof_bytes = hex::decode(&proof).expect("Invalid proof hex");
            let vdf = WesolowskiVDF::new(&challenge_bytes);
            
            let output = if let (Some(a_str), Some(b_str), Some(c_str)) = (output_a, output_b, output_c) {
                // Use provided output values
                let a = BigInt::parse_bytes(a_str.as_bytes(), 10).expect("Invalid output_a");
                let b = BigInt::parse_bytes(b_str.as_bytes(), 10).expect("Invalid output_b");
                let _ = BigInt::parse_bytes(c_str.as_bytes(), 10).expect("Invalid output_c");
                ClassGroupElement::new(a, b, vdf.discriminant.clone())
            } else {
                // Fall back to recomputing (this is what was causing the issue)
                let (computed_output, _) = vdf.compute(iterations);
                println!("Debug: Using computed output for verification (fallback mode)");
                computed_output
            };
            
            let is_valid = vdf.verify(&output, &proof_bytes, iterations);
            
            if is_valid {
                println!("Proof is valid");
            } else {
                println!("Proof is invalid");
            }
        }
        
        Commands::Benchmark => {
            // Create a VDF instance for benchmarking
            let vdf = WesolowskiVDF::new(b"benchmark_challenge");
            
            // Run the comprehensive benchmark
            let benchmark_report = vdf.benchmark();
            println!("{}", benchmark_report);
            
            // Also run the quick iteration finder for comparison
            let target_iterations = benchmark_iterations();
            println!("\nQuick benchmark result for 100ms-1000ms range: {} iterations", target_iterations);
            println!("\nExample usage:");
            println!("cargo run --release -- compute \"test_challenge\" {}", target_iterations);
        }
    }
}
