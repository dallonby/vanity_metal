#!/bin/bash
# Build script for vanity_metal on macOS with Apple Silicon
#
# Usage:
#   ./build.sh          # Build in release mode
#   ./build.sh debug    # Build in debug mode

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

MODE="${1:-release}"

echo "Building vanity_metal (Metal GPU vanity address generator)"
echo "Mode: $MODE"
echo ""

# Compile Metal shader to metallib
echo "Compiling Metal shader..."
xcrun -sdk macosx metal -c shader.metal -o shader.air
xcrun -sdk macosx metallib shader.air -o shader.metallib
rm shader.air
echo "  -> shader.metallib"

# Build Swift executable
echo "Building Swift executable..."
if [ "$MODE" = "debug" ]; then
    swift build
    cp .build/debug/vanity_metal ./vanity_metal
else
    swift build -c release
    cp .build/release/vanity_metal ./vanity_metal
fi

echo ""
echo "Build complete! Run with:"
echo "  ./vanity_metal --count 10 --prefix c0ffee"
echo ""
echo "Options:"
echo "  --count, -c      Number of addresses to generate (default: 10)"
echo "  --prefix, -p     Address prefix without 0x (default: c0ffee)"
echo "  --iterations, -i Iterations per GPU thread (default: 1000)"
