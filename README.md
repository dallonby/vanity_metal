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

1. **Secure Random Generation**: Uses `SecRandomCopyBytes` (CSPRNG) for private keys
2. **Precomputation**: GPU computes initial public keys via scalar multiplication
3. **Incremental Search**: Each iteration just adds G to the current point (O(1) vs O(256))
4. **Keccak-256**: Hashes the public key to derive the address
5. **Prefix Match**: Checks if address starts with target prefix

## Architecture

```
shader.metal   - Metal compute shader (secp256k1 + keccak256)
main.swift     - Host code to manage GPU dispatch
Package.swift  - Swift package manifest
build.sh       - Build script
```

## Security Notes

**CRITICAL**: This tool uses `SecRandomCopyBytes` (Apple's CSPRNG) for all private key generation.

### Why This Matters: The Profanity1 Disaster

The original Profanity vanity generator had a catastrophic vulnerability:
- Used a **weak 32-bit random seed** for key generation
- Attackers could brute-force the seed space in minutes
- Led to the **Wintermute hack (~$160M stolen)** in September 2022
- Multiple other wallets were drained using the same attack

### Our Approach

- **256-bit entropy**: Each private key uses 256 bits from `SecRandomCopyBytes`
- **No seed-based PRNG**: We don't use any deterministic random number generators
- **Fresh randomness per batch**: Each batch gets new entropy from the OS
- **No GPU-side random**: All randomness comes from the secure CPU-side CSPRNG

### Verification Recommendations

1. **Verify on air-gapped machine**: Derive the address independently using a trusted tool
2. **Check entropy source**: Run `log show --predicate 'subsystem == "com.apple.securityd"'` to verify CSPRNG usage
3. **Small test first**: Generate a test address and verify it works before using for real funds
4. **Immediate transfer**: Move any funds through the vanity address quickly; don't use as long-term storage
