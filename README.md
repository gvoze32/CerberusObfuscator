# Cerberus Obfuscator

**Advanced Multi-Layer Python Code Obfuscator with Binary Compilation Support**

The Cerberus Obfuscator is an advanced Python obfuscation toolkit that implements multi-layer architecture to protect Python code from reverse engineering and analysis. Named after the three-headed guardian dog from Greek mythology, this tool uses various layered security techniques to make code extremely difficult to analyze.

## Key Features

🔐 **Multi-Layer Protection Architecture** - 5-layer obfuscation system  
🔧 **Binary Compilation Support** - Built-in Nuitka integration  
🛡️ **Advanced Anti-Debug Mechanisms** - Process monitoring and detection  
🌐 **GitHub Gist Integration** - One-time execution enforcement  
⚡ **Standalone Mode** - Offline execution capability  
🔒 **Enhanced Encryption** - AES-256-CBC + PBKDF2 key derivation  
🎯 **Smart RAM Detection** - Automatic compilation optimization  

## Installation

### Prerequisites
```bash
# Install Python 3.8+
# Install pip dependencies
pip install -r requirements.txt

# Optional: For binary compilation
pip install nuitka
```

### Dependencies
- `requests>=2.28.0` - For GitHub Gist API
- `pycryptodome>=3.17.0` - For AES encryption
- `nuitka` (optional) - For binary compilation
- `psutil` (optional) - For RAM detection and anti-debug features

## Usage

### Command Line Interface
```bash
# Basic obfuscation (standalone mode):
python cerberus.py -i input_file.py -o output_file.py

# With GitHub Gist (one-time execution):
python cerberus.py -i input_file.py -o output_file.py --token YOUR_GITHUB_TOKEN

# Binary compilation:
python cerberus.py -i input_file.py -o output_file --binary

# Disable anti-debug (for testing):
python cerberus.py -i input_file.py -o output_file.py --no-debug-checks
```

### Command Line Parameters
- `-i, --input`: Python file to obfuscate (required)
- `-o, --output`: Output file for obfuscated code (required)
- `--token`: GitHub Personal Access Token (optional, enables one-time execution via Gist)
- `--binary`: Compile to binary using Nuitka (optional)
- `--no-debug-checks`: Disable anti-debug mechanisms (optional)

### Execution Modes

#### GitHub Gist Mode (with --token)
- **One-time execution**: File can only be run once
- **Internet required**: Must have connectivity for Gist validation
- **Maximum security**: External validation system
- **Dependencies**: `requests` + `pycryptodome`

#### Standalone Mode (without --token)
- **Multiple executions**: File can be run multiple times
- **No internet required**: Works completely offline
- **Local protection**: Self-contained anti-tampering
- **Dependencies**: `pycryptodome` only

#### Binary Mode (with --binary)
- **Native executable**: No Python interpreter required on target
- **No dependencies**: Self-contained binary
- **Enhanced protection**: Additional compilation-level obfuscation
- **Cross-platform**: Supports Windows, Linux, macOS

### GitHub Token Setup
1. Go to GitHub Settings → Developer settings → Personal access tokens
2. Generate new token with `gist` scope
3. Copy token and use with `--token` parameter

## Practical Examples

### Example Input File (example.py)
```python
def calculate_sum(a, b):
    """Calculate the sum of two numbers"""
    result = a + b
    message = f"The sum is {result}"
    print(message)
    return result

if __name__ == "__main__":
    x = 10
    y = 20
    total = calculate_sum(x, y)
```

### Basic Obfuscation (Standalone Mode)
```bash
python cerberus.py -i example.py -o example_protected.py
```

**Output:**
```
[+] Starting Cerberus Obfuscation (standalone mode)...
  [*] Layer 0: Enhanced source cleaning and preparation...
  [*] Layer 1: Advanced AST transformations...
  [*] Layer 2: AES-256-CBC encryption and serialization...
  [*] Layer 3: Advanced compression and multi-layer encoding...
  [*] Layer 4: Creating enhanced standalone loader...
[+] Cerberus obfuscation complete!
[+] Successfully obfuscated example.py -> example_protected.py
[+] Standalone mode: No GitHub Gist created
[!] The obfuscated file can be executed multiple times
[!] Cerberus security features (standalone):
    - XOR encryption (reliable)
    - Base64→Hex encoding (stable)
    - Import preservation (compatible)
    - Anti-debug mechanisms
[!] Required dependency on target system:
    - pycryptodome
```

### With GitHub Gist (One-time execution)
```bash
python cerberus.py -i example.py -o example_gist.py --token ghp_xxxxxxxxxxxx
```

**Output:**
```
[+] Starting Cerberus Obfuscation (with GitHub Gist)...
  [*] Layer 0: Enhanced source cleaning and preparation...
  [*] Layer 1: Advanced AST transformations...
  [*] Layer 2: AES-256-CBC encryption and serialization...
  [*] Layer 3: Advanced compression and multi-layer encoding...
  [*] Layer 4: Creating enhanced loader with GitHub Gist...
[+] Cerberus obfuscation complete!
[+] Successfully obfuscated example.py -> example_gist.py
[+] GitHub Gist ID: x9y8z7w6v5u4t3s2r1q0
[+] Status file: status_AbCdEfGhIjKlMnOp.json
[!] WARNING: The obfuscated file can only be executed ONCE!
[!] Cerberus security features:
    - XOR encryption (reliable)
    - Base64→Hex encoding (stable)
    - Anti-debug mechanisms (when enabled)
    - Import preservation (compatible)
```

### Binary Compilation
```bash
python cerberus.py -i example.py -o example_binary --binary
```

**Output:**
```
[+] Starting Cerberus Obfuscation (standalone mode)...
  [*] Layer 0: Enhanced source cleaning and preparation...
  [*] Layer 1: Advanced AST transformations...
  [*] Layer 2: AES-256-CBC encryption and serialization...
  [*] Layer 3: Advanced compression and multi-layer encoding...
  [*] Layer 4: Creating enhanced standalone loader...
  [*] Layer 5: Compiling to binary with Nuitka...
  [*] System RAM: 16.0GB
  [*] Sufficient RAM available, using standard compilation
  [+] Found Nuitka: nuitka3
  [*] Compiling with Nuitka (nuitka3) using standard settings...
  [+] Binary compiled successfully: example_binary
[+] Cerberus obfuscation complete!
Binary compiled: example_binary
```

## Core Features

### Multi-Layer Protection Architecture

**Layer 0: Enhanced Preparation**
- Advanced source code cleaning with AST manipulation
- Enhanced anti-tampering mechanisms
- Self-tamper detection with integrity validation

**Layer 1: Advanced AST Transformations**
- Enhanced name obfuscation with confusing patterns
- Advanced string encryption using AES-256-CBC
- Sophisticated integer obfuscation
- Enhanced control flow flattening with state machines
- More sophisticated junk code injection

**Layer 2: Enhanced Encryption & Serialization**
- AES-256-CBC encryption (instead of ECB)
- PBKDF2 key derivation with 100,000 iterations
- XOR encryption with dynamic key generation
- Marshal serialization for binary format

**Layer 3: Advanced Compression & Encoding**
- zlib compression with maximum level
- Multi-layer Base64 → Hexadecimal encoding
- Scrambled hex encoding for additional obfuscation

**Layer 4: Enhanced Protection & Distribution**
- GitHub Gist integration with JSON status tracking
- Enhanced self-destruct mechanism
- Private gist creation for better security
- Standalone mode with local anti-tampering

**Layer 5: Binary Compilation (Optional)**
- Nuitka binary compilation with automatic optimization
- RAM detection for compilation settings
- Cross-platform binary generation
- No dependencies required on target system

## Security Features

### Enhanced Anti-Debug Mechanisms
- **Process Monitoring**: Detects debugging tools (gdb, lldb, ida, ollydbg, x64dbg)
- **Timing Analysis**: Detects debugger-induced slowdowns
- **Memory Analysis**: Monitors unusual object counts
- **Thread-Based Monitoring**: Background anti-debug checks
- **Self-Tamper Detection**: File modification time validation

### Advanced Encryption
- **AES-256-CBC**: Industry-standard encryption with proper IV
- **PBKDF2 Key Derivation**: 100,000 iterations for key strengthening
- **Dynamic Keys**: Generated based on GitHub token or random seed
- **Multi-Layer Encoding**: Base64 → Hex → Scrambled patterns

### Network-Based Protection (Gist Mode)
- **Private Gist Creation**: Enhanced security over public gists
- **JSON Status Tracking**: Structured validation system
- **Expiration Mechanism**: 24-hour automatic expiration
- **Usage Tracking**: Client information logging
- **Fail-Closed Security**: Silent exit on validation failure

### Binary Compilation Features
- **Smart RAM Detection**: Automatic optimization based on available memory
- **Low-Memory Mode**: Optimized compilation for systems <8GB RAM
- **Multi-Command Support**: Fallback to different Nuitka installations
- **Error Handling**: Graceful fallback to Python code if compilation fails
- **Cross-Platform**: Supports Windows (.exe), Linux, and macOS binaries

## Advanced Configuration

### RAM Optimization
The tool automatically detects system RAM and optimizes Nuitka compilation:
- **<8GB RAM**: Uses `--low-memory` flag for reduced memory consumption
- **≥8GB RAM**: Uses standard compilation settings for faster build times

### Anti-Debug Configuration
Anti-debug features can be disabled for testing:
```bash
python cerberus.py -i input.py -o output.py --no-debug-checks
```

## Important Notes

1. **Version 2.0**: This is an enhanced version with advanced features
2. **One-Time Execution**: Gist mode files can only be executed ONCE
3. **Internet Dependency**: Gist mode requires internet connection
4. **GitHub Token**: Token with gist scope required for Gist mode
5. **Binary Dependencies**: Nuitka required for binary compilation
6. **Irreversible**: Obfuscation process cannot be reversed
7. **Legal Compliance**: Use only for legitimate purposes

## System Requirements

### Minimum Requirements
- Python 3.8+
- 4GB RAM (8GB+ recommended for binary compilation)
- Internet connection (for Gist mode only)

### Recommended Setup
- Python 3.9+
- 16GB RAM (for optimal binary compilation)
- SSD storage (faster compilation times)
- Recent Nuitka version (for binary features)

## Error Handling & Troubleshooting

### Common Issues
1. **Nuitka Not Found**: Install with `pip install nuitka`
2. **Low Memory**: Tool automatically uses `--low-memory` mode
3. **GitHub API Limits**: Use different token or wait for reset
4. **Compilation Timeout**: Increases automatically for large files

### Debug Mode
Disable anti-debug features during development:
```bash
python cerberus.py -i input.py -o output.py --no-debug-checks
```

## License

**Educational and Research Purposes Only**

This software is provided for educational and legitimate security research purposes only. The developers are not responsible for any misuse of this tool.

---

**Author**: gvoze32  
**Version**: 2.0  
**Enhanced Features**: Binary compilation, advanced anti-debug, AES-256-CBC, PBKDF2