import Foundation

// Test Keccak implementation against known vectors
// Private key 1 -> public key G -> address should be known

// Uncompressed public key for private key 1 (generator point G):
// 04 + x + y where:
// x = 79BE667E F9DCBBAC 55A06295 CE870B07 029BFCDB 2DCE28D9 59F2815B 16F81798
// y = 483ADA77 26A3C465 5DA4FBFC 0E1108A8 FD17B448 A6855419 9C47D08F FB10D4B8

// For Ethereum, we hash JUST x || y (64 bytes), NOT the 04 prefix
let x: [UInt8] = [
    0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC,
    0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87, 0x0B, 0x07,
    0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9,
    0x59, 0xF2, 0x81, 0x5B, 0x16, 0xF8, 0x17, 0x98
]

let y: [UInt8] = [
    0x48, 0x3A, 0xDA, 0x77, 0x26, 0xA3, 0xC4, 0x65,
    0x5D, 0xA4, 0xFB, 0xFC, 0x0E, 0x11, 0x08, 0xA8,
    0xFD, 0x17, 0xB4, 0x48, 0xA6, 0x85, 0x54, 0x19,
    0x9C, 0x47, 0xD0, 0x8F, 0xFB, 0x10, 0xD4, 0xB8
]

let pubkey = x + y

print("Public key (64 bytes):")
print(pubkey.map { String(format: "%02x", $0) }.joined())

// Now compute Keccak-256 to verify
// Expected address for private key 1: 0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf
// Which means the hash of x||y should start with (after skipping first 12 bytes):
// 7E 5F 45 52 09 1A 69 12 5d 5D fC b7 b8 C2 65 90 29 39 5B df

print("\nExpected address: 0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf")
print("Expected hash bytes 12-31: 7e5f4552091a69125d5dfcb7b8c2659029395bdf")

// Let me call out to an external tool to verify the keccak hash
let process = Process()
process.executableURL = URL(fileURLWithPath: "/usr/bin/env")
process.arguments = ["python3", "-c", """
from Crypto.Hash import keccak
x = bytes.fromhex('79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798')
y = bytes.fromhex('483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8')
pubkey = x + y
k = keccak.new(digest_bits=256)
k.update(pubkey)
h = k.hexdigest()
print(f'Full hash: {h}')
print(f'Address (bytes 12-31): 0x{h[24:]}')
"""]
try? process.run()
process.waitUntilExit()
