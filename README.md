# Vivar Engine SDK

Vivar Engine SDK is a professional-grade Post-Quantum Cryptography (PQC) toolkit. It provides high-performance, memory-safe cryptographic primitives based on the **Kyber768** algorithm to ensure data confidentiality and integrity in the post-quantum era.

## Key Features

- **Post-Quantum Ready:** Implements NIST-approved Kyber768 for KEM (Key Encapsulation Mechanism).
- **Memory Safety:** Developed in **Rust**, ensuring complete protection against common memory vulnerabilities (buffer overflows, leaks).
- **Binary-Safe Encryption:** Deterministic streaming encryption that allows processing of any file format (PDFs, images, binaries) without corruption.
- **High Performance:** Compiled as a C-ABI shared library (`.so`, `.dll`), making it natively compatible with Python, C++, Go, and more.
- **Zero-Knowledge Architecture:** Designed for client-side encryption, ensuring maximum privacy.

## Technical Specifications

| Feature | Specification |
| :--- | :--- |
| **Algorithm** | Kyber768 (PQC-KEM) |
| **KDF** | HKDF with SHA-256 |
| **Memory Management** | Zeroize on drop |
| **Language** | Rust (Core) |
| **Interface** | C-FFI |

## Getting Started

### Prerequisites
- Rust (for compilation)
- A C-compatible host language (e.g., Python 3.x)

### Compilation
To compile the engine as a shared library:
```bash
cargo build --release
