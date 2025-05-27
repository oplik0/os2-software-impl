# OS2 Software Implementation

[![CI](https://github.com/username/os2-software-impl/workflows/CI/badge.svg)](https://github.com/username/os2-software-impl/actions)
[![Performance Tracking](https://github.com/username/os2-software-impl/workflows/Performance%20Tracking/badge.svg)](https://github.com/username/os2-software-impl/actions)

A Rust implementation of the OS2 (Oblivious Substring Search) protocol, providing a software baseline for comparison with hardware-accelerated implementations such as FPGA designs.

## Overview

This implementation provides:
- **Complete Paillier cryptosystem** with configurable key sizes (512, 1024, 2048, 4096 bits)
- **Bloom filter-based document indexing** with homomorphic encryption
- **Client-server OS2 protocol** supporting encrypted document storage and similarity search
- **Comprehensive benchmarks** for performance comparison with hardware implementations
- **Hardware comparison framework** for evaluating FPGA acceleration benefits

## Architecture

### Core Components

1. **Paillier Cryptosystem** (`src/paillier.rs`)
   - Probabilistic public-key encryption
   - Homomorphic addition and scalar multiplication
   - Custom prime generation with Miller-Rabin primality testing

2. **Bloom Filters** (`src/lib.rs`)
   - Sliding window keyword hashing
   - Homomorphic encryption of filter bits
   - Collision-resistant similarity computation

3. **OS2 Protocol** (`src/lib.rs`)
   - Document outsourcing with encrypted indexing
   - Privacy-preserving query evaluation
   - Client-side similarity score computation

4. **Symmetric Encryption** (`src/lib.rs`)
   - AES-GCM for document content encryption
   - Authenticated encryption with associated data

## Quick Start

### Prerequisites

- Rust 1.86+ (stable toolchain - possible previous version work, but untested)
- Cargo package manager

### Building

```bash
# Clone the repository
git clone https://github.com/username/os2-software-impl.git
cd os2-software-impl

# Build the project
cargo build --release

# Run tests
cargo test

# Run benchmarks
cargo bench
```

### Basic Usage

```rust
use os2_software_impl::*;

// Create client and server
let client = Os2Client::new();
let mut server = CloudServer::new();
server.receive_paillier_pk(client.get_paillier_pk_for_server());

// Outsource a document
let doc = client.outsource_document(
    "doc1",
    "FPGA implementation of cryptographic accelerators",
    vec!["fpga", "crypto", "accelerators"]
)?;
server.store_document(doc);

// Perform encrypted search
let query = client.generate_query_bloom_filter(vec!["fpga", "crypto"]);
let results = server.evaluate_query(&query);

// Process results
for (doc_id, encrypted_result) in results {
    let similarity = client.process_search_result(&encrypted_result);
    println!("Document {} similarity: {:.4}", doc_id, similarity);
}
```

## Testing

### Unit Tests
```bash
cargo test --lib
```

### Integration Tests
```bash
cargo test --test integration_tests
```

### All Tests with Output
```bash
cargo test -- --nocapture
```

## Benchmarking

### Quick Benchmarks
```bash
# Core crypto operations
cargo bench --bench crypto_benchmarks

# OS2 protocol workflows
cargo bench --bench os2_benchmarks
```

### Comprehensive Performance Analysis
```bash
# Run all benchmarks with detailed output
cargo bench -- --output-format html

# Results available in target/criterion/
```

### Benchmark Categories

1. **Cryptographic Operations**
   - Paillier key generation (multiple key sizes)
   - Encryption/decryption performance
   - Homomorphic operations (addition, scalar multiplication)

2. **Bloom Filter Operations**
   - Creation and keyword insertion
   - Encryption/decryption with Paillier
   - Hash function performance (SHA-256)

3. **Protocol Operations**
   - Document outsourcing (end-to-end)
   - Query generation and evaluation
   - Result processing and similarity calculation

4. **Scalability Analysis**
   - Performance vs. number of documents
   - Memory usage patterns
   - Throughput measurements

## Hardware Comparison

### Performance Baseline

This software implementation provides baseline metrics for comparison with hardware accelerators:

| Operation | Software Performance | FPGA Target |
|-----------|---------------------|-------------|
| Paillier Keygen (1024-bit) | TBD | TBD |
| Paillier Encrypt | TBD | TBD |
| Bloom Filter Encrypt (128-bit) | TBD | TBD |
| OS2 Query (10 docs) | TBD | TBD |

### Hardware Implementation Targets

#### FPGA Acceleration
- **Platform**: TBD

### Validation Framework

Hardware implementations should:
1. **Produce identical results** to this software baseline
2. **Pass all test vectors** from the test suite
3. **Maintain security properties** (semantic security, privacy)
4. **Demonstrate performance improvements** over software baseline

## CI/CD Pipeline

### Automated Testing
- **Continuous Integration**: Tests run on every push and PR
- **Multiple Rust Versions**: Stable and beta channel testing
- **Code Quality**: Formatting (rustfmt) and linting (clippy)
- **Security Audits**: Dependency vulnerability scanning

### Performance Tracking
- **Weekly Benchmarks**: Automated performance regression detection
- **Baseline Generation**: Performance data for hardware comparison
- **Trend Analysis**: Long-term performance evolution tracking
- **Comparison Reports**: Hardware vs software analysis templates

### Artifacts
- **Test Results**: Detailed test output and coverage
- **Benchmark Data**: JSON and HTML performance reports
- **Hardware Templates**: Comparison frameworks and test vectors
- **Release Binaries**: Optimized builds for deployment

## Project Structure

```
├── src/
│   ├── lib.rs              # Main OS2 implementation
│   └── paillier.rs         # Paillier cryptosystem
├── tests/
│   ├── integration_tests.rs # End-to-end protocol tests
│   └── unit_tests.rs       # Component unit tests
├── benches/
│   ├── crypto_benchmarks.rs # Cryptographic operation benchmarks
│   └── os2_benchmarks.rs   # Protocol workflow benchmarks
├── .github/
│   └── workflows/
│       ├── ci.yml          # Continuous integration
│       └── performance-tracking.yml # Automated benchmarking
└── target/
    └── criterion/          # Benchmark results and reports
```

## Dependencies

### Core Dependencies
- `num-bigint`: Arbitrary precision integer arithmetic
- `num-integer`: Integer operations and traits
- `rand`: Cryptographically secure random number generation
- `sha2`: SHA-256 hash functions
- `aes-gcm`: AES-GCM symmetric encryption

### Development Dependencies
- `criterion`: Statistical benchmarking framework
- `serde`: Serialization for benchmark data export
- `chrono`: Timestamp generation for performance tracking

## Performance Considerations

### Key Size Recommendations
- **Development/Testing**: 512-bit keys for fast iteration
- **Production/Comparison**: 1024-2048 bit keys for security
- **Hardware Evaluation**: Match target hardware capabilities

### Optimization Opportunities
1. **Parallel Paillier Operations**: Multiple independent encryptions
2. **Batch Bloom Filter Processing**: SIMD-optimized hash computation
3. **Memory Layout**: Cache-friendly data structures
4. **Algorithm Selection**: Hardware-optimized modular arithmetic

## Contributing

### Development Workflow
1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass: `cargo test`
5. Run benchmarks: `cargo bench`
6. Submit a pull request

### Code Style
- Use `cargo fmt` for consistent formatting
- Address `cargo clippy` warnings
- Add documentation for public APIs
- Include tests for new features

### Performance Changes
- Run benchmarks before and after changes
- Document performance impact in PR description
- Consider hardware implementation implications

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- OS2 protocol design from [original paper reference]
- Paillier cryptosystem implementation based on [Paillier 1999]
- Bloom filter implementation optimized for homomorphic encryption
- Benchmarking framework designed for hardware comparison

## Hardware Collaboration

This software implementation is designed to facilitate hardware acceleration research. For collaboration on FPGA implementations:

1. **Use this software as the reference implementation**
2. **Validate hardware designs against our test suite**
3. **Compare performance using our benchmark framework**
4. **Contribute hardware-specific optimizations back to the project**

Contact: [maintainer email] for hardware acceleration partnerships.
