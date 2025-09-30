# Third-Party Libraries for ICSSploit

This directory contains third-party libraries integrated as git submodules for enhanced protocol support.

## pydnp3

**Status**: ✅ Works with Python 3.10 | ⚠️ Build Issues with Python 3.11+

[pydnp3](https://github.com/ChargePoint/pydnp3) provides Python bindings for the [opendnp3](https://github.com/automatak/dnp3) C++ library, offering robust DNP3 protocol support.

### Features
- Full DNP3 protocol stack implementation
- Asynchronous communication handling
- Production-ready reliability
- Comprehensive DNP3 object support

### Python Version Compatibility

| Python Version | Status | Notes |
|---------------|--------|-------|
| 3.9 | ✅ Compatible | Some deprecation warnings |
| 3.10 | ✅ **Recommended** | Full compatibility, builds successfully |
| 3.11+ | ❌ Build Fails | pybind11 compatibility issues |

### Recommended Setup

For the best experience, use Python 3.10:

```bash
# Create Python 3.10 environment
conda create -n icssploit python=3.10 -y
conda activate icssploit

# Install build dependencies
conda install cmake make gcc_linux-64 gxx_linux-64 -y  # Linux
# or
brew install cmake make gcc  # macOS

# Install ICSSploit dependencies
pip install -r requirements.txt

# Build pydnp3
./scripts/build_pydnp3.sh
```

### Build Instructions

#### Option 1: Automated Build Script (Recommended)
```bash
# Run the automated build script
./scripts/build_pydnp3.sh
```

#### Option 2: Manual Build
```bash
# Navigate to pydnp3 directory
cd thirdparty/pydnp3

# Ensure submodules are initialized
git submodule update --init --recursive

# Build and install
python setup.py build
python setup.py develop
```

### Build Requirements

**Linux:**
```bash
conda install cmake make gcc_linux-64 gxx_linux-64 -y
```

**macOS:**
```bash
brew install cmake make gcc
```

**Windows:**
- Visual Studio Build Tools 2019 or later
- CMake 3.10+
- Git (for submodules)

### Known Issues

**Python 3.11+ Compatibility**: The pydnp3 library uses an older version of pybind11 that has compatibility issues with Python 3.11+. Build errors include:

- `PyFrameObject` structure access issues
- Deprecated Python C API usage
- `PyThread_*` function deprecation warnings

### Solutions

1. **✅ Use Python 3.10**: **Recommended** - Full compatibility, builds successfully
2. **🔄 Fallback Implementation**: ICSSploit DNP3 client automatically falls back to raw protocol implementation if pydnp3 is not available
3. **⏳ Future Updates**: The pydnp3 project may be updated to support newer Python versions

### Integration Status

The ICSSploit DNP3 client (`src/modules/clients/dnp3_client.py`) supports dual-mode operation:

- **Primary Mode**: Uses pydnp3 when available (preferred)
- **Fallback Mode**: Uses raw DNP3 protocol implementation (always functional)

### Testing

```bash
# Test pydnp3 availability
python3 -c "import pydnp3; print('pydnp3 available')"

# Test ICSSploit DNP3 client
python3 -c "from src.modules.clients.dnp3_client import DNP3Client; print('DNP3 client ready')"
```

## Future Libraries

Additional protocol libraries may be added as submodules:
- Modbus libraries for enhanced Modbus support
- OPC UA libraries for advanced OPC UA features
- Additional industrial protocol implementations

## Contributing

When adding new third-party libraries:

1. Add as git submodule: `git submodule add <repo-url> thirdparty/<name>`
2. Create build scripts in `scripts/` directory
3. Update client implementations to support dual-mode operation
4. Document integration status and known issues
5. Ensure fallback implementations remain functional
