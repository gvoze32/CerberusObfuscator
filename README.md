# Cerberus Obfuscator Suite

**Advanced Multi-Layer Python Code Obfuscator with Dual Implementation**

The Cerberus Obfuscator Suite is an advanced Python obfuscation toolkit that implements multi-layer architecture to protect Python code from reverse engineering and analysis. Named after the three-headed guardian dog from Greek mythology, this tool uses various layered security techniques to make code extremely difficult to analyze.

## Available Tools

This project includes two powerful obfuscators:

### Cerberus Original
- Primary Focus: Python Obfuscation
- Output Format: Python Files Only
- Reliable and proven architecture
- Simple setup and configuration

### CerberusBin
- Primary Focus: Binary Compilation
- Output Format: Python + Binary Options
- Built-in Nuitka Support for binary compilation
- Enhanced security features

## Installation

### Prerequisites
```bash
# Install Python 3.8+
# Install pip dependencies
pip install -r requirements.txt

# Optional: For binary compilation (CerberusBin only)
pip install nuitka
```

### Dependencies
- `requests>=2.28.0` - For GitHub Gist API
- `pycryptodome>=3.17.0` - For AES encryption
- `nuitka` (optional) - For binary compilation in CerberusBin

## Usage

### Cerberus Original

#### Basic Usage
```bash
# With GitHub Gist (one-time execution):
python cerberus.py -i input_file.py -o output_file.py --token YOUR_GITHUB_TOKEN

# Standalone mode (no internet required):
python cerberus.py -i input_file.py -o output_file.py
```

### CerberusBin

#### Basic Usage
```bash
# With GitHub Gist (one-time execution):
python cerberusbin.py -i input_file.py -o output_file.py --token YOUR_GITHUB_TOKEN

# Standalone mode (no internet required):
python cerberusbin.py -i input_file.py -o output_file.py

# Binary compilation (main feature):
python cerberusbin.py -i input_file.py -o output_file --binary

# Disable anti-debug (for testing):
python cerberusbin.py -i input_file.py -o output_file.py --no-debug-checks
```

### Command Line Parameters
- `-i, --input`: Python file to obfuscate
- `-o, --output`: Output file for obfuscated code
- `--token`: GitHub Personal Access Token (optional, enables one-time execution via Gist)
- `--binary`: (CerberusBin only) Compile to binary using Nuitka
- `--no-debug-checks`: (CerberusBin only) Disable anti-debug mechanisms

### Execution Modes

#### GitHub Gist Mode (with --token)
- One-time execution: File can only be run once
- Internet required: Must have connectivity for Gist validation
- Maximum security: External validation system
- Dependencies: `requests` + `pycryptodome`

#### Standalone Mode (without --token)
- Multiple executions: File can be run multiple times
- No internet required: Works completely offline
- Local protection: Self-contained anti-tampering
- Dependencies: `pycryptodome` only

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

### Using Cerberus Original

#### With GitHub Gist (One-time execution)
```bash
python cerberus.py -i example.py -o example_protected.py --token ghp_xxxxxxxxxxxx
```

**Output:**
```
[+] Starting Cerberus Obfuscation Process (with GitHub Gist)...
  [*] Layer 0: Cleaning source code...
  [*] Layer 1: Applying AST transformations...
  [*] Layer 2: Encrypting and serializing...
  [*] Layer 3: Compressing and encoding...
  [*] Layer 4: Creating GitHub Gist and loader stub...
[+] Obfuscation complete!
[+] Successfully obfuscated example.py -> example_protected.py
[+] GitHub Gist ID: a1b2c3d4e5f6g7h8i9j0
[!] WARNING: The obfuscated file can only be executed ONCE!
```

#### Standalone Mode (Multiple executions)
```bash
python cerberus.py -i example.py -o example_standalone.py
```

**Output:**
```
[+] Starting Cerberus Obfuscation Process (standalone mode)...
  [*] Layer 0: Cleaning source code...
  [*] Layer 1: Applying AST transformations...
  [*] Layer 2: Encrypting and serializing...
  [*] Layer 3: Compressing and encoding...
  [*] Layer 4: Creating standalone loader stub...
[+] Obfuscation complete!
[+] Successfully obfuscated example.py -> example_standalone.py
[+] Standalone mode: No GitHub Gist created
[!] The obfuscated file can be executed multiple times
[!] Required dependency on target system: pycryptodome
```

### Using CerberusBin

#### With GitHub Gist (One-time execution)
```bash
python cerberusbin.py -i example.py -o example_advanced.py --token ghp_xxxxxxxxxxxx
```

**Output:**
```
[+] Starting CerberusBin Obfuscation (with GitHub Gist)...
  [*] Layer 0: Enhanced source cleaning and preparation...
  [*] Layer 1: Reliable AST transformations...
  [*] Layer 2: Unified encryption and serialization...
  [*] Layer 3: Reliable compression and encoding...
  [*] Layer 4: Creating unified loader with GitHub Gist...
[+] CerberusBin obfuscation complete!
[+] Successfully obfuscated example.py -> example_advanced.py
[+] GitHub Gist ID: x9y8z7w6v5u4t3s2r1q0
[!] WARNING: The obfuscated file can only be executed ONCE!
```

#### Standalone Mode (Multiple executions)
```bash
python cerberusbin.py -i example.py -o example_standalone_advanced.py
```

**Output:**
```
[+] Starting CerberusBin Obfuscation (standalone mode)...
  [*] Layer 0: Enhanced source cleaning and preparation...
  [*] Layer 1: Reliable AST transformations...
  [*] Layer 2: Unified encryption and serialization...
  [*] Layer 3: Reliable compression and encoding...
  [*] Layer 4: Creating unified standalone loader...
[+] CerberusBin obfuscation complete!
[+] Successfully obfuscated example.py -> example_standalone_advanced.py
[+] Standalone mode: No GitHub Gist created
[!] The obfuscated file can be executed multiple times
```

#### Binary Compilation
```bash
python cerberusbin.py -i example.py -o example_binary --binary
```

**Output:**
```
[+] Starting CerberusBin Obfuscation with Binary Compilation...
  [*] Layer 0: Enhanced source cleaning and preparation...
  [*] Layer 1: Reliable AST transformations...
  [*] Layer 2: Unified encryption and serialization...
  [*] Layer 3: Reliable compression and encoding...
  [*] Layer 4: Creating unified standalone loader...
  [*] Layer 5: Compiling to binary with Nuitka...
[+] Binary compilation complete!
[+] Successfully created: example_binary.exe
[!] Binary can be executed multiple times
[!] No dependencies required on target system
```

## Core Features

### Multi-Layer Protection Architecture

**Layer 0: Initialization & Preparation**
- Source code cleaning (remove comments and docstrings)
- Anti-tampering mechanisms with hash verification
- Code integrity validation before execution

**Layer 1: AST Transformations**
- Name Obfuscation: Replace variable, function, and class names
- String Encryption: Encrypt all string literals
- Integer Obfuscation: Replace integer constants with expressions
- Control Flow Flattening: Transform program flow into state machines
- Dead Code Injection: Inject fake code and opaque predicates

**Layer 2: Encryption & Serialization**
- XOR encryption with random 256-bit keys
- Marshal serialization for binary format
- Reliable encryption pipeline

**Layer 3: Compression & Encoding**
- zlib compression to reduce size
- Base64 to Hexadecimal encoding
- Stable payload encoding

**Layer 4: Protection & Distribution**
- GitHub Gist integration for execution tracking (optional)
- Self-destruct mechanism after single execution (Gist mode)
- Standalone mode for offline execution

**Layer 5: Binary Compilation (CerberusBin only)**
- Nuitka binary compilation support
- Native executable generation
- No dependencies required on target system

## Security Features

### Standard Protection (Both Tools)
- Anti-tampering with hash verification
- Silent exit on modification detection
- Multi-layer encoding protection
- Control flow obfuscation
- Dead code injection

### Enhanced Protection (CerberusBin)
- Advanced anti-debug mechanisms
- Thread-based monitoring
- Process name detection
- Memory protection features
- Binary compilation support

### Network-Based Protection (Gist Mode)
- Internet dependency for execution
- GitHub Gist validation system
- Fail-closed security model
- One-time execution enforcement

## Important Notes

1. **One-Time Execution**: Obfuscated files with Gist mode can only be executed ONCE
2. **Internet Dependency**: Gist mode requires internet connection for execution
3. **GitHub Token**: Token with gist scope required for Gist mode
4. **Irreversible**: Obfuscation process cannot be reversed without original code
5. **Legal Compliance**: Use only for legitimate purposes and educational research

## When to Use Each Tool

### Use Cerberus Original for:
- Simple obfuscation needs
- Educational purposes
- Quick prototyping
- Lightweight protection

### Use CerberusBin for:
- Binary compilation requirements
- Enhanced security features
- Professional projects
- Native executable distribution

## License

**Educational and Research Purposes Only**

This software is provided for educational and legitimate security research purposes only. The developers are not responsible for any misuse of this tool.

## Author

**gvoze32** - Advanced Python Obfuscation Research

---

**"Protecting Python Code Through Advanced Obfuscation"** - Cerberus Obfuscator Suite 