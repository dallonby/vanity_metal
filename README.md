# Vanity Metal - GPU Accelerated Ethereum Address Generator

High-performance vanity Ethereum address generator using Apple Metal for GPU acceleration on Apple Silicon (M1/M2/M3/M4).

## Requirements

- macOS 13+ (Ventura or later)
- Apple Silicon Mac (M1/M2/M3/M4)
- Xcode Command Line Tools (`xcode-select --install`)

## Building

```bash
cd src/bin/vanity_metal
./build.sh
```

## Usage

```bash
# Generate 10 addresses with 0xbadbad prefix (default)
./vanity_metal

# Generate 20 addresses with custom prefix
./vanity_metal --count 20 --prefix dead

# Tune GPU workload (more iterations = more work per dispatch)
./vanity_metal --count 10 --prefix badbad --iterations 2000
```

## Performance

Expected performance on Apple Silicon:

| Chip | Approximate Speed |
|------|-------------------|
| M1   | ~2-3M keys/sec    |
| M1 Pro/Max | ~4-6M keys/sec |
| M2   | ~3-4M keys/sec    |
| M2 Pro/Max | ~5-8M keys/sec |
| M3   | ~4-5M keys/sec    |
| M3 Pro/Max | ~7-12M keys/sec |
| M4   | ~5-7M keys/sec    |
| M4 Pro/Max | ~10-15M keys/sec |

Note: Actual performance depends on prefix length. Longer prefixes require more attempts:
- 4 chars (0xdead): ~65K attempts average
- 6 chars (0xc0ffee): ~16M attempts average
- 8 chars (0xdeadbeef): ~4B attempts average

## How It Works

1. **GPU Threads**: Launches thousands of parallel GPU threads
2. **Scalar Multiplication**: Each thread computes `k*G` on secp256k1 curve
3. **Keccak-256**: Hashes the public key to derive the address
4. **Prefix Match**: Checks if address starts with target prefix
5. **Atomic Results**: Found keys are atomically stored in results buffer

## Architecture

```
shader.metal   - Metal compute shader (secp256k1 + keccak256)
main.swift     - Host code to manage GPU dispatch
Package.swift  - Swift package manifest
build.sh       - Build script
```

## Security Notes

- Private keys are generated using `UInt64.random()` which uses the system CSPRNG
- Keys are never written to disk during generation
- For production use, verify generated addresses on a separate trusted machine
