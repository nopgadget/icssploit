#!/bin/bash
# Build script for pydnp3 with Python version compatibility checks
# This script attempts to build pydnp3 and handles version compatibility issues

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
PYDNP3_DIR="$PROJECT_ROOT/thirdparty/pydnp3"

echo "=== Building pydnp3 for ICSSploit ==="
echo "Project root: $PROJECT_ROOT"
echo "pydnp3 directory: $PYDNP3_DIR"

# Check if pydnp3 submodule exists
if [ ! -d "$PYDNP3_DIR" ]; then
    echo "Error: pydnp3 submodule not found at $PYDNP3_DIR"
    echo "Please run: git submodule update --init --recursive"
    exit 1
fi

cd "$PYDNP3_DIR"

# Check Python version
PYTHON_VERSION=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
echo "Python version: $PYTHON_VERSION"

# Provide specific guidance based on Python version
case "$PYTHON_VERSION" in
    "3.9")
        echo "✅ Python 3.9 - Compatible with some warnings"
        ;;
    "3.10")
        echo "✅ Python 3.10 - Recommended version, full compatibility"
        ;;
    "3.11"|"3.12"|"3.13")
        echo "⚠️  Python $PYTHON_VERSION - Known compatibility issues with pydnp3"
        echo "   Build may fail due to deprecated Python C API usage in pybind11"
        echo "   Consider using Python 3.10 for best results"
        ;;
    *)
        echo "❓ Python $PYTHON_VERSION - Untested version"
        ;;
esac

# Check if we have the necessary build tools
echo "Checking build dependencies..."
if ! command -v cmake &> /dev/null; then
    echo "Error: cmake not found. Please install cmake."
    exit 1
fi

if ! command -v g++ &> /dev/null; then
    echo "Error: g++ not found. Please install a C++ compiler."
    exit 1
fi

echo "Build tools found: cmake $(cmake --version | head -n1), g++ $(g++ --version | head -n1)"

# Try to build with error handling
echo "Attempting to build pydnp3..."
echo "Note: This may fail with Python 3.11+ due to deprecated API usage"

# Create a build log
BUILD_LOG="$PROJECT_ROOT/pydnp3_build.log"
echo "Build log will be saved to: $BUILD_LOG"

# Attempt the build
if python3 setup.py build 2>&1 | tee "$BUILD_LOG"; then
    echo "✅ pydnp3 build succeeded!"
    
    # Try to install in development mode
    if python3 setup.py develop 2>&1 | tee -a "$BUILD_LOG"; then
        echo "✅ pydnp3 installed successfully!"
        
        # Test the installation
        if python3 -c "import pydnp3; print('pydnp3 import successful')" 2>&1 | tee -a "$BUILD_LOG"; then
            echo "✅ pydnp3 import test passed!"
            echo ""
            echo "pydnp3 is now available for use in ICSSploit DNP3 client."
            exit 0
        else
            echo "❌ pydnp3 import test failed"
        fi
    else
        echo "❌ pydnp3 installation failed"
    fi
else
    echo "❌ pydnp3 build failed"
fi

echo ""
echo "❌ Build failed. This is likely due to Python version compatibility issues."
echo "   The ICSSploit DNP3 client will automatically fall back to raw protocol implementation."
echo ""
echo "💡 Possible solutions:"
echo "   1. ✅ Use Python 3.10 for best compatibility (recommended)"
echo "   2. ✅ Use Python 3.9 (compatible with warnings)"
echo "   3. ⏳ Wait for pydnp3 updates to support newer Python versions"
echo "   4. 🔄 Use the raw DNP3 implementation (already functional, no build required)"
echo ""
echo "📋 Build log saved to: $BUILD_LOG"
echo "   The DNP3 client will work without pydnp3 - this is not a critical failure."
exit 1
