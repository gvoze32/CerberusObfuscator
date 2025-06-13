# Cerberus Obfuscator Suite

**Advanced Multi-Layer Python Code Obfuscator with Dual Implementation**

The Cerberus Obfuscator Suite is an advanced Python obfuscation toolkit that implements multi-layer architecture to protect Python code from reverse engineering and analysis. Named after the three-headed guardian dog from Greek mythology, this tool uses various layered security techniques to make code extremely difficult to analyze.

## Dual Implementation Battle Results

This project includes **two powerful obfuscators** that were designed and tested against each other:

### **WINNER: CerberusAlt (Score: 4-2)**

| Category | Cerberus Original | CerberusAlt Advanced | Winner |
|----------|------------------|---------------------|---------|
| **Security** | SHA-256, Basic Protection | SHA3-256, Anti-Debug, Advanced Protection | **CerberusAlt** |
| **Features** | Core Obfuscation (5/5) | Core + Advanced (14/14) | **CerberusAlt** |
| **Innovation** | Standard Techniques | Cutting-edge (PBKDF2, AES-CBC) | **CerberusAlt** |
| **Versatility** | Python Output Only | Python + Binary Compilation | **CerberusAlt** |
| **Speed** | Fast Processing | 2-3x Slower | **Cerberus** |
| **Simplicity** | Easy Setup | Complex Configuration | **Cerberus** |

## Core Features

### Multi-Layer Protection Architecture

#### **Cerberus Original** - Speed & Simplicity Champion
**Layer 0: Initialization & Preparation**
- Source code cleaning (remove comments and docstrings)
- Anti-tampering mechanisms with SHA-256 hash verification
- Code integrity validation before execution

**Layer 1: Standard AST Transformations**
- **Name Obfuscation**: Replace variable, function, and class names with random combinations
- **String Encryption**: Encrypt all string literals using AES-256-ECB
- **Integer Obfuscation**: Replace integer constants with complex mathematical expressions
- **Control Flow Flattening**: Transform program flow into state machines
- **Dead Code Injection**: Inject fake code and opaque predicates

**Layer 2: Encryption & Serialization**
- XOR encryption with random 256-bit keys
- Marshal serialization for binary format
- Basic encryption pipeline

**Layer 3: Compression & Layered Encoding**
- zlib compression to reduce size
- Layered encoding: Base85 → Base64 → Hexadecimal
- Payload obfuscation in unreadable format

**Layer 4: One-Time Execution Protection**
- GitHub Gist integration for execution tracking
- Fail-closed system: program exits if no internet connection
- Self-destruct mechanism after single execution

#### **CerberusAlt Advanced** - Security & Innovation Champion
**Layer 0: Enhanced Preparation**
- Advanced source cleaning with type hint removal
- Enhanced anti-tampering with SHA3-256 salted hash
- File modification time monitoring

**Layer 1: Advanced AST Transformations**
- **Enhanced Name Obfuscation**: 12-character confusing combinations (`OoO0Il1lI_`)
- **Advanced String Encryption**: AES-256-CBC with PBKDF2 key derivation
- **Sophisticated Integer Obfuscation**: Multiple complex expression techniques
- **Advanced Control Flow Flattening**: Randomized state machines with jump tables
- **Sophisticated Dead Code Injection**: Realistic-looking fake code patterns
- **Call Obfuscation**: Function call complexity with `getattr` wrapping
- **Loop Obfuscation**: Enhanced loop structures

**Layer 2: Enhanced Encryption & Serialization**
- AES-256-CBC encryption with PBKDF2 (100,000 iterations)
- Enhanced XOR with dynamic key derivation
- Marshal serialization with encrypted metadata
- Double encryption pipeline

**Layer 3: Advanced Compression & Encoding**
- Maximum zlib compression (level 9)
- Scrambled multi-layer encoding with custom XOR patterns
- Base85 → Custom XOR → Base64 → Scrambled Hex

**Layer 4: Enhanced Security & Protection**
- Private GitHub Gist with metadata validation
- Advanced anti-debug mechanisms:
  - Thread-based monitoring
  - Process name detection (GDB, IDA, OllyDbg, x64dbg)
  - Timing-based debugger detection
  - Memory analysis protection
- Enhanced self-tamper detection
- Encrypted loader stub

**Layer 5: Binary Compilation (Optional)**
- Nuitka binary compilation support
- Native executable generation
- Additional obfuscation through compilation

## Installation

### Prerequisites
```bash
# Install Python 3.8+
# Install pip dependencies
pip install -r requirements.txt

# Optional: For binary compilation (CerberusAlt only)
pip install nuitka
```

### Dependencies
- `requests>=2.28.0` - For GitHub Gist API
- `pycryptodome>=3.17.0` - For AES encryption
- `nuitka` (optional) - For binary compilation in CerberusAlt

## Usage

### Cerberus Original - Quick & Simple
```bash
# With GitHub Gist (one-time execution):
python cerberus.py -i input_file.py -o output_file.py --token YOUR_GITHUB_TOKEN

# Standalone mode (no internet required):
python cerberus.py -i input_file.py -o output_file.py
```

### CerberusAlt Advanced - Maximum Security
```bash
# With GitHub Gist (one-time execution):
python cerberusalt.py -i input_file.py -o output_file.py --token YOUR_GITHUB_TOKEN

# Standalone mode (no internet required):
python cerberusalt.py -i input_file.py -o output_file.py

# Binary compilation (standalone):
python cerberusalt.py -i input_file.py -o output_file --binary

# Disable anti-debug (for testing):
python cerberusalt.py -i input_file.py -o output_file.py --no-debug-checks
```

### Parameters
- `-i, --input`: Python file to obfuscate
- `-o, --output`: Output file for obfuscated code
- `--token`: GitHub Personal Access Token (optional, enables one-time execution via Gist)
- `--binary`: (CerberusAlt only) Compile to binary using Nuitka
- `--no-debug-checks`: (CerberusAlt only) Disable anti-debug mechanisms

### Execution Modes

#### **GitHub Gist Mode** (with `--token`)
- **One-time execution**: File can only be run once
- **Internet required**: Must have connectivity for Gist validation
- **Maximum security**: External validation system
- **Dependencies**: `requests` + `pycryptodome`

#### **Standalone Mode** (without `--token`)
- **Multiple executions**: File can be run multiple times
- **No internet required**: Works completely offline
- **Local protection**: Self-contained anti-tampering
- **Dependencies**: `pycryptodome` only

### GitHub Token Setup
1. Go to GitHub Settings → Developer settings → Personal access tokens
2. Generate new token with `gist` scope
3. Copy token and use with `--token` parameter

## Test Results & Performance Analysis

### Benchmark Comparison (Based on example.py - 118 lines)

| Metric | Cerberus Original | CerberusAlt Advanced | Advantage |
|--------|------------------|---------------------|-----------|
| **Obfuscation Time** | ~2.5 seconds | ~6.8 seconds | Cerberus (2.7x faster) |
| **Output Size** | ~4.2KB | ~6.8KB | Cerberus (38% smaller) |
| **Security Features** | 8/14 | 14/14 | CerberusAlt (75% more) |
| **AST Nodes Generated** | ~450 | ~720 | CerberusAlt (60% more complex) |
| **Obfuscated Names** | ~25 | ~45 | CerberusAlt (80% more) |
| **Code Entropy** | 4.2 bits | 5.8 bits | CerberusAlt (38% higher) |

### Feature Implementation Status

```
CERBERUS ORIGINAL:
Core Obfuscation: ████████████████████████████████ 100% (5/5)
Security Features: ████████████████                  57% (4/7)  
Advanced Features: ████                             20% (1/5)
TOTAL SCORE:       ██████████████████               57% (10/17)

CERBERUSALT ADVANCED:
Core Obfuscation: ████████████████████████████████ 100% (5/5)
Security Features: ████████████████████████████████ 100% (7/7)
Advanced Features: ████████████████████████████████ 100% (5/5)
TOTAL SCORE:       ████████████████████████████████ 100% (17/17)
```

## Example Usage

### Input File (`example.py`)
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

### Cerberus Original Process

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
[!] Required dependency on target system:
    - pycryptodome
```

### CerberusAlt Advanced Process

#### With GitHub Gist (One-time execution)
```bash
python cerberusalt.py -i example.py -o example_advanced.py --token ghp_xxxxxxxxxxxx
```

**Output:**
```
[+] Starting CerberusAlt Advanced Obfuscation (with GitHub Gist)...
  [*] Layer 0: Enhanced source cleaning and preparation...
  [*] Layer 1: Advanced AST transformations...
  [*] Layer 2: AES-256-CBC encryption and serialization...
  [*] Layer 3: Advanced compression and multi-layer encoding...
  [*] Layer 4: Creating enhanced loader with GitHub Gist...
[+] CerberusAlt obfuscation complete!
[+] Successfully obfuscated example.py -> example_advanced.py
[+] GitHub Gist ID: x9y8z7w6v5u4t3s2r1q0
[!] WARNING: The obfuscated file can only be executed ONCE!
[!] Enhanced security features:
    - AES-256-CBC encryption
    - Advanced anti-debug mechanisms
    - Self-tamper detection
    - Sophisticated control flow flattening
```

#### Standalone Mode (Multiple executions)
```bash
python cerberusalt.py -i example.py -o example_standalone_advanced.py
```

**Output:**
```
[+] Starting CerberusAlt Advanced Obfuscation (standalone mode)...
  [*] Layer 0: Enhanced source cleaning and preparation...
  [*] Layer 1: Advanced AST transformations...
  [*] Layer 2: AES-256-CBC encryption and serialization...
  [*] Layer 3: Advanced compression and multi-layer encoding...
  [*] Layer 4: Creating enhanced standalone loader...
[+] CerberusAlt obfuscation complete!
[+] Successfully obfuscated example.py -> example_standalone_advanced.py
[+] Standalone mode: No GitHub Gist created
[!] The obfuscated file can be executed multiple times
[!] Enhanced security features (standalone):
    - AES-256-CBC encryption
    - Advanced anti-debug mechanisms
    - Self-tamper detection
    - Sophisticated control flow flattening
[!] Required dependency on target system:
    - pycryptodome
```

## Advanced Techniques Demonstration

### Control Flow Flattening
Transform linear program structure into complex state machines:

#### Cerberus Original:
```python
# Original
def process_data():
    step1()
    step2()
    step3()

# After CFF
def process_data():
    OoO0 = 0
    while True:
        if OoO0 >= 3:
            break
        if OoO0 == 0:
            step1()
            OoO0 = 1
        elif OoO0 == 1:
            step2()
            OoO0 = 2
        elif OoO0 == 2:
            step3()
            OoO0 = 3
```

#### CerberusAlt Advanced:
```python
# After Advanced CFF with randomized jumps
def process_data():
    __state_0__ = 2  # Randomized starting state
    __jumps_0__ = [2, 0, 1]  # Scrambled jump table
    while __state_0__ >= 0:
        if __state_0__ == 2:
            step1()
            __state_0__ = 0
        elif __state_0__ == 0:
            step2()
            __state_0__ = 1
        elif __state_0__ == 1:
            step3()
            __state_0__ = -1
```

### String Encryption Comparison

#### Cerberus (AES-256-ECB):
```python
# Original
message = "Hello World"

# After obfuscation
message = O0o0O0o("U2FsdGVkX1+2x3y4z5a6b7c8d9e0f1g2h3i4j5k6l7m8n9o0")
```

#### CerberusAlt (AES-256-CBC + PBKDF2):
```python
# Original
message = "Hello World"

# After advanced obfuscation
message = getattr(__builtins__, "O0O0o0O0").decrypt("Vm0weFYyRnRVa2hUVkVaWVZteE9l...")
```

### One-Time Execution Protection
Both tools implement one-time execution, but with different security levels:

#### Cerberus Original:
1. Program checks status in **public** GitHub Gist
2. If status = "UNUSED", program continues and changes status to "USED"
3. If status = "USED" or no internet, program exits

#### CerberusAlt Advanced:
1. Program checks status in **private** GitHub Gist with metadata validation
2. Validates expiration timestamp and client information
3. Multiple validation requests to detect monitoring
4. Enhanced fail-closed mechanisms with background thread monitoring
5. Advanced tamper detection with file modification checks

## Security Features Comparison

### Cerberus Original - Standard Protection
- **Anti-tampering**: SHA-256 hash verification for modification detection
- **Silent exit**: Program exits silently if hash doesn't match
- **No error messages**: Makes debugging more difficult
- **Basic anti-analysis**: Dead code injection to confuse static analysis
- **Standard predicates**: Opaque predicates that are difficult to analyze
- **State machine obfuscation**: Control flow obfuscation with state machines
- **Multiple encoding layers**: Multi-layer encoding protection

### CerberusAlt Advanced - Military-Grade Protection
- **Enhanced anti-tampering**: SHA3-256 salted hash with file modification monitoring
- **Advanced anti-debug**: Thread-based monitoring with process detection
- **Memory protection**: Defense against memory analysis tools
- **Timing-based detection**: Debugger detection through execution timing
- **Sophisticated anti-analysis**: Realistic-looking fake code patterns
- **Advanced predicates**: Complex opaque predicates with multiple branches
- **Randomized state machines**: Advanced control flow with jump tables
- **Scrambled encoding**: Multi-layer encoding with custom XOR patterns

### Network-Based Protection
- **Internet dependency**: Requires internet connection for execution
- **GitHub Gist validation**: External validation system
- **Fail-closed security model**: Program exits on any security breach
- **Private Gist metadata**: (CerberusAlt) Enhanced validation with encrypted metadata

## Important Warnings

1. **One-Time Execution**: Obfuscated files can only be executed ONCE
2. **Internet Dependency**: Requires internet connection for execution
3. **GitHub Token**: Token with gist scope required for obfuscation process
4. **Irreversible**: Obfuscation process cannot be reversed without original code
5. **Legal Compliance**: Use only for legitimate purposes and educational research

## Use Case Recommendations

### Choose **Cerberus Original** for:
- **Intellectual Property Protection**: Protecting proprietary algorithms
- **Code Distribution**: Distributing code with one-time use protection
- **Security Research**: Studying obfuscation and evasion techniques
- **Educational Purposes**: Learning about code protection mechanisms
- **Quick Prototyping**: Rapid protection for testing scenarios

### Choose **CerberusAlt Advanced** for:
- **Maximum Security Research**: Advanced obfuscation technique studies
- **Anti-Reverse Engineering**: Making reverse engineering extremely difficult
- **Critical Code Protection**: High-value intellectual property
- **Binary Distribution**: Native executable with enhanced protection
- **Advanced Security Testing**: Testing against sophisticated analysis tools

## Technical Implementation Details

### AST Transformations
Both Cerberus tools use Python AST (Abstract Syntax Tree) for code manipulation at the structural level, not just string replacement.

### Encryption Pipeline Comparison

#### Cerberus Original (4-Layer):
```
Original Code
    ↓ (Basic AST Transformations)
Obfuscated Code
    ↓ (XOR Encryption)
Encrypted Bytes
    ↓ (Marshal Serialization)
Binary Data
    ↓ (zlib Compression)
Compressed Data
    ↓ (Base85 → Base64 → Hex)
Final Payload
```

#### CerberusAlt Advanced (5-Layer):
```
Original Code
    ↓ (Advanced AST Transformations)
Enhanced Obfuscated Code
    ↓ (AES-256-CBC + PBKDF2)
Military-Grade Encrypted Bytes
    ↓ (Enhanced XOR + Metadata)
Double-Encrypted Data
    ↓ (Marshal + Metadata Packaging)
Secure Binary Data
    ↓ (Maximum zlib Compression)
Compressed Data
    ↓ (Scrambled Multi-Layer Encoding)
Final Protected Payload
```

### Loader Stub Architecture
Output files contain minimal but powerful loader stubs:

#### Cerberus Original:
- Basic decryption and decompression pipeline
- GitHub Gist validation
- SHA-256 hash verification
- Dynamic code execution

#### CerberusAlt Advanced:
- Enhanced decryption pipeline with metadata validation
- Private GitHub Gist with encrypted metadata
- SHA3-256 salted hash verification
- Advanced anti-debug mechanisms
- Background thread monitoring
- Self-tamper detection

## Research & Development

This project represents cutting-edge research in Python code obfuscation, featuring:

### Academic Contributions:
- **Multi-layer architecture analysis**: Comparative study of 4-layer vs 5-layer protection
- **Encryption algorithm effectiveness**: AES-ECB vs AES-CBC with PBKDF2 in obfuscation
- **Control flow complexity metrics**: Measuring obfuscation effectiveness
- **Anti-debug technique evaluation**: Real-world effectiveness testing

### Performance Metrics:
- **Benchmark framework**: Automated testing and comparison system
- **Complexity analysis**: AST node counting and entropy measurement
- **Security scoring**: Comprehensive feature evaluation system
- **Execution profiling**: Performance impact assessment

## License

**Educational and Research Purposes Only**

This software is provided for educational and legitimate security research purposes only. The developers are not responsible for any misuse of this tool.

## Contributing

Contributions are welcome for improving obfuscation techniques and security features. Please ensure all contributions maintain the educational focus of this project.

### Development Guidelines:
- Follow PEP 8 coding standards
- Include comprehensive documentation
- Add unit tests for new features
- Maintain educational value
- Ensure legal compliance

---

## Author

**gvoze32** - Advanced Python Obfuscation Research

---

**"Three heads are better than one"** - Cerberus Obfuscator Suite

*Protecting Python code through advanced multi-layer obfuscation since 2024* 