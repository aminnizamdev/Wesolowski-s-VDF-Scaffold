# Wesolowski VDF Scaffold

A modular implementation scaffold for the Wesolowski Verifiable Delay Function using class groups of binary quadratic forms. This project provides a complete foundation for VDF research and development with a focus on educational clarity and modular architecture.

## Overview

This implementation demonstrates the core mathematical and cryptographic components required for a Wesolowski VDF system. It includes class group operations, discriminant generation, proof construction, and verification mechanisms organized in a clean, modular structure.

## Architecture

The project is structured into four main modules:

### Core Modules

- **`class_group`** - Binary quadratic form operations and class group arithmetic
- **`crypto`** - Cryptographic utilities including discriminant generation and primality testing
- **`vdf`** - Complete VDF implementation with computation, proof generation, and verification
- **`main`** - Command-line interface for VDF operations

### Mathematical Foundation

The implementation is built on:

- **Binary Quadratic Forms**: Expressions of the form `ax² + bxy + cy²` with discriminant `Δ = b² - 4ac < 0`
- **Class Group Operations**: Composition and reduction operations that form the algebraic structure
- **Sequential Computation**: Repeated squaring operations `g^(2^t)` that provide the delay function property

## Features

### VDF Operations

- **Computation**: Sequential squaring in class groups with configurable iteration count
- **Proof Generation**: Non-interactive proof construction using Fiat-Shamir heuristic
- **Verification**: Efficient proof verification significantly faster than computation
- **Benchmarking**: Performance analysis tools for iteration calibration

### Cryptographic Components

- **Discriminant Generation**: Cryptographically secure negative discriminants with proper mathematical properties
- **Prime Generation**: Deterministic challenge prime generation for proof systems
- **Miller-Rabin Testing**: Probabilistic primality testing for efficiency
- **SHA-256 Hashing**: Cryptographic hash functions for all randomness generation

### CLI Interface

- **Compute Command**: Generate VDF outputs and proofs
- **Verify Command**: Validate proofs against outputs
- **Benchmark Command**: Performance analysis and iteration calibration

## Installation

### Prerequisites

- Rust 1.70+ with 2024 edition support
- Cargo package manager

### Dependencies

```toml
sha2 = "0.10"           # Cryptographic hashing
clap = "4.0"            # Command-line interface
hex = "0.4"             # Hexadecimal encoding
num-bigint = "0.4"      # Arbitrary precision integers
num-traits = "0.2"      # Numeric trait abstractions
once_cell = "1.19"      # Lazy static initialization
```

### Build

```bash
# Clone the repository
git clone https://github.com/aminnizamdev/Wesolowski-s-VDF-Scaffold.git
cd Wesolowski-s-VDF-Scaffold

# Build the project
cargo build --release

# Run tests
cargo test

# Check code quality
cargo clippy
```

## Usage

### Command Line Interface

#### Compute VDF Output and Proof

```bash
# Basic computation
cargo run --release -- compute "challenge_string" 100

# Using hex-encoded challenge
cargo run --release -- compute "48656c6c6f" 50
```

#### Verify VDF Proof

```bash
# Verify with explicit output components
cargo run --release -- verify "challenge" 100 "proof_hex" \
  --output-a "123456" --output-b "789012" --output-c "345678"

# Verify with recomputation (fallback)
cargo run --release -- verify "challenge" 100 "proof_hex"
```

#### Performance Benchmarking

```bash
# Run comprehensive benchmark
cargo run --release -- benchmark
```

### Library Usage

```rust
use wesolowski_vdf::{WesolowskiVDF, ClassGroupElement};

// Initialize VDF with challenge
let vdf = WesolowskiVDF::new(b"your_challenge_here");

// Compute output and proof
let (output, proof) = vdf.compute(100);

// Verify the proof
let is_valid = vdf.verify(&output, &proof, 100);
assert!(is_valid);
```

## Implementation Details

### Class Group Operations

The `ClassGroupElement` struct represents binary quadratic forms `(a, b, c)` with:

- **Composition**: Combines two forms using the NUCOMP algorithm approach
- **Reduction**: Maintains forms in reduced representation for efficiency
- **Squaring**: Optimized self-composition for repeated operations
- **Serialization**: Compact binary representation for proof systems

### Discriminant Generation

Discriminants are generated with the following properties:

- **Negative Values**: Required for definite binary quadratic forms
- **Congruence**: Must satisfy `D ≡ 1 (mod 4)` for proper class group structure
- **Bit Length**: Configurable security parameter (default: 1024 bits)
- **Deterministic**: Generated from challenge using SHA-256

### Proof System

The verification equation follows the Wesolowski construction:

```
y = π^l · g^r where l·q + r = 2^t
```

Where:
- `y` is the computed output
- `π` is the proof element
- `l` is the challenge prime
- `q, r` are quotient and remainder from division
- `t` is the iteration count

## Performance Characteristics

### Computational Complexity

- **Computation Time**: O(t) where t is iteration count
- **Proof Size**: O(log t) bits (effectively constant)
- **Verification Time**: O(log t) operations
- **Memory Usage**: O(1) space complexity

### Benchmarking Results

The benchmark command provides detailed performance analysis including:

- Iteration timing across different counts
- Memory usage patterns
- Verification performance ratios
- Recommended parameters for target delays

## Security Considerations

### Mathematical Properties

- **Sequentiality**: No known method for significant parallelization
- **Soundness**: Invalid proofs rejected with high probability
- **Completeness**: Valid computations always produce verifiable proofs

### Implementation Notes

- All randomness derived from cryptographic hash functions
- Discriminants generated with proper mathematical constraints
- Miller-Rabin primality testing with sufficient rounds
- Constant-time operations where feasible

## Development

### Code Quality

```bash
# Format code
cargo fmt

# Run linter
cargo clippy

# Clean build artifacts
cargo clean
```

### Module Structure

```
src/
├── lib.rs          # Library interface and exports
├── main.rs         # CLI application entry point
├── class_group.rs  # Binary quadratic form operations
├── crypto.rs       # Cryptographic utilities
└── vdf.rs          # VDF implementation and proof system
```

## Limitations

This implementation is designed as a research and educational scaffold:

- **Performance**: Not optimized for production-scale deployments
- **Security Audit**: Has not undergone formal cryptographic review
- **Parameter Selection**: Uses standard parameters suitable for demonstration
- **Platform Support**: Developed and tested on standard desktop environments

## Contributing

Contributions are welcome for:

- Performance optimizations
- Additional test coverage
- Documentation improvements
- Security enhancements
- Platform compatibility

## License

This project is provided as-is for research and educational purposes. Please review the license file for specific terms and conditions.

## References

- Wesolowski, B. "Efficient verifiable delay functions." EUROCRYPT 2019
- Binary quadratic forms and class group theory
- Fiat-Shamir heuristic for non-interactive proofs
- NUCOMP algorithm for class group operations