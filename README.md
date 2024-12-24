# Secret Sharing in Rust

This project implements **Shamir's Secret Sharing (SS)**, **Feldman Verifiable Secret Sharing (VSS), and Pedersen Verifiable Secret Sharing (VSS)** using the `sm2` crate for finite field arithmetic. The project includes:

- Polynomial generation over finite fields
- Secret sharing and reconstruction using Lagrange interpolation
- Verifiable Secret Sharing using Feldman's and Pedersen's schemes

## Usage

To run the project:
```bash
cargo run
```

To run the tests:
```bash
cargo test
```

## Modules

### `polynomial`

This module provides functionalities for polynomial operations over finite fields. It includes features for creating polynomials, evaluating them at specific points, and generating Feldman and Pedersen commitments for the polynomial coefficients.

### `secret_sharing`

This module implements the core logic for Shamir's Secret Sharing, Feldman VSS, and Pedersen VSS. It allows for the generation of shares from a secret, reconstruction of the secret from shares, and verification of shares using commitments.

## Dependencies

- `sm2`: For finite field arithmetic and elliptic curve operations.
- `rand`: For secure random number generation.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.