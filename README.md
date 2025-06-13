# Cerberus Obfuscator 🐺

**Advanced Multi-Layer Python Code Obfuscator**

Cerberus Obfuscator adalah alat obfuskasi Python canggih yang mengimplementasikan arsitektur multi-layer untuk melindungi kode Python dari reverse engineering dan analisis. Dinamai berdasarkan anjing penjaga tiga kepala dari mitologi Yunani, alat ini menggunakan berbagai teknik keamanan berlapis untuk membuat kode menjadi sangat sulit dianalisis.

## 🔒 Fitur Utama

### Arsitektur Multi-Layer Protection

**Layer 0: Initialization & Preparation**
- Pembersihan kode sumber (hapus komentar dan docstrings)
- Mekanisme anti-tampering dengan SHA-256 hash verification
- Validasi integritas kode sebelum eksekusi

**Layer 1: Advanced AST Transformations**
- **Name Obfuscation**: Mengganti nama variabel, fungsi, dan kelas dengan kombinasi acak
- **String Encryption**: Enkripsi semua string literal menggunakan AES-256
- **Integer Obfuscation**: Mengganti konstanta integer dengan ekspresi matematika kompleks
- **Control Flow Flattening**: Mengubah alur program menjadi state machine
- **Dead Code Injection**: Menyuntikkan kode palsu dan opaque predicates

**Layer 2: Encryption & Serialization**
- XOR encryption dengan kunci acak 256-bit
- Marshal serialization untuk format biner
- Multi-layer encryption pipeline

**Layer 3: Compression & Layered Encoding**
- Kompresi zlib untuk mengurangi ukuran
- Encoding berlapis: Base85 → Base64 → Hexadecimal
- Obfuskasi payload dalam format yang tidak dapat dibaca

**Layer 4: One-Time Execution Protection**
- Integrasi GitHub Gist untuk tracking eksekusi
- Sistem fail-closed: program keluar jika tidak ada koneksi internet
- Mekanisme self-destruct setelah satu kali eksekusi

## 🚀 Installation

### Prerequisites
```bash
# Install Python 3.8+
# Install pip dependencies
pip install -r requirements.txt
```

### Dependencies
- `requests>=2.28.0` - Untuk API GitHub Gist
- `pycryptodome>=3.17.0` - Untuk enkripsi AES

## 📖 Usage

### Basic Usage
```bash
python cerberus.py -i input_file.py -o output_file.py --token YOUR_GITHUB_TOKEN
```

### Parameters
- `-i, --input`: File Python yang akan di-obfuskasi
- `-o, --output`: File output hasil obfuskasi
- `--token`: GitHub Personal Access Token (diperlukan untuk Gist creation)

### GitHub Token Setup
1. Buka GitHub Settings → Developer settings → Personal access tokens
2. Generate new token dengan scope `gist`
3. Copy token dan gunakan dengan parameter `--token`

## 🔧 Example

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

### Obfuscation Process
```bash
python cerberus.py -i example.py -o example_protected.py --token ghp_xxxxxxxxxxxx
```

### Output
```
[+] Starting Cerberus Obfuscation Process...
  [*] Layer 0: Cleaning source code...
  [*] Layer 1: Applying AST transformations...
  [*] Layer 2: Encrypting and serializing...
  [*] Layer 3: Compressing and encoding...
  [*] Layer 4: Creating GitHub Gist and loader stub...
[+] Obfuscation complete!
[+] Successfully obfuscated example.py -> example_protected.py
[+] GitHub Gist ID: a1b2c3d4e5f6g7h8i9j0
[+] Status file: k1l2m3n4o5p6.txt
[!] WARNING: The obfuscated file can only be executed ONCE!
```

## ⚡ Advanced Features

### Control Flow Flattening
Mengubah struktur program linear menjadi state machine yang kompleks:
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

### String Encryption
Semua string literal dienkripsi menggunakan AES-256:
```python
# Original
message = "Hello World"

# After obfuscation
message = O0o0O0o("U2FsdGVkX1+2x3y4z5a6b7c8d9e0f1g2h3i4j5k6l7m8n9o0")
```

### One-Time Execution
File yang ter-obfuskasi hanya dapat dijalankan sekali:
1. Saat pertama kali dijalankan, program cek status di GitHub Gist
2. Jika status = "UNUSED", program lanjut eksekusi dan ubah status ke "USED"
3. Jika status = "USED" atau tidak ada koneksi internet, program keluar

## 🛡️ Security Features

### Anti-Tampering
- SHA-256 hash verification untuk deteksi modifikasi
- Program keluar silent jika hash tidak cocok
- Tidak ada pesan error untuk mempersulit debugging

### Anti-Analysis
- Dead code injection untuk mengecoh static analysis
- Opaque predicates yang sulit dianalisis
- Control flow obfuscation dengan state machine
- Multiple encoding layers

### Network-Based Protection
- Dependency pada koneksi internet untuk eksekusi
- GitHub Gist sebagai external validation
- Fail-closed security model

## ⚠️ Important Warnings

1. **One-Time Execution**: File yang di-obfuskasi hanya dapat dijalankan SATU KALI
2. **Internet Dependency**: Memerlukan koneksi internet untuk eksekusi
3. **GitHub Token**: Token dengan scope gist diperlukan untuk proses obfuskasi
4. **Irreversible**: Proses obfuskasi tidak dapat di-reverse tanpa kode asli

## 🎯 Use Cases

- **Malware Development**: Proteksi payload dari analisis sandbox
- **Intellectual Property Protection**: Melindungi algoritma proprietary
- **Anti-Reverse Engineering**: Mempersulit proses reverse engineering
- **Code Distribution**: Distribusi kode dengan proteksi one-time use
- **Security Research**: Studi teknik obfuskasi dan evasion

## 🔧 Technical Details

### Transformasi AST
Cerberus menggunakan Python AST (Abstract Syntax Tree) untuk manipulasi kode di level struktur, bukan sekedar string replacement.

### Encryption Pipeline
```
Original Code
    ↓ (AST Transformations)
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

### Loader Stub
File output berisi loader stub yang minimal namun powerful:
- Decryption dan decompression pipeline
- GitHub Gist validation
- Hash verification
- Dynamic code execution

## 📄 License

Educational and research purposes only. Tidak bertanggung jawab atas penyalahgunaan alat ini.

## 🤝 Contributing

Kontribusi dipersilakan untuk peningkatan teknik obfuskasi dan fitur keamanan.

---

**"Three heads are better than one"** - Cerberus Project Team 