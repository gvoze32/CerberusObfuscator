#!/usr/bin/env python3
"""
CerberusAlt - Advanced Multi-Layer Python Obfuscator (Alternative Implementation)
Author: Advanced Cyber Security Team
Version: 2.0

Enhanced Features:
- AES-256-CBC encryption (instead of ECB)
- Advanced anti-debug mechanisms
- Self-tamper detection
- Nuitka binary compilation support
- Enhanced control flow flattening
- More sophisticated junk code injection
- Dynamic key generation with PBKDF2

Dependencies:
- requests
- pycryptodome
- nuitka (optional, for binary compilation)

Usage:
python cerberusalt.py -i <input.py> -o <output.py> --token <github_token> [--binary]
"""

import ast
import argparse
import base64
import binascii
import hashlib
import marshal
import os
import random
import string
import sys
import time
import zlib
import subprocess
from typing import Dict, List, Set, Any, Optional
import requests
from Cryptodome.Cipher import AES
from Cryptodome.Protocol.KDF import PBKDF2
from Cryptodome.Random import get_random_bytes
from Cryptodome.Util.Padding import pad, unpad


class CerberusAltObfuscator:
    def __init__(self, github_token: str, use_binary: bool = False):
        self.github_token = github_token
        self.use_binary = use_binary
        self.api_headers = {
            'Authorization': f'token {github_token}',
            'Accept': 'application/vnd.github.v3+json',
            'User-Agent': 'CerberusAlt/2.0'
        }
        
        # Enhanced encryption setup
        self.master_salt = get_random_bytes(32)
        self.aes_key = PBKDF2(github_token, self.master_salt, 32, count=100000)
        self.aes_iv = get_random_bytes(16)
        self.xor_key = None
        self.original_hash = None
        self.gist_id = None
        self.gist_filename = None
        
        # Anti-debug settings
        self.debug_checks = True
        self.tamper_checks = True
        
    def generate_obfuscated_name(self, length: int = 12) -> str:
        """Generate more complex obfuscated names using extended character set"""
        chars = 'OoO0Il1lI_'  # More confusing characters
        return ''.join(random.choice(chars) for _ in range(length))
    
    def apply_anti_debug_checks(self) -> str:
        """Generate anti-debug and self-tamper detection code"""
        return f'''
import sys, os, time, threading, psutil, gc
from datetime import datetime

def {self.generate_obfuscated_name()}():
    # Anti-debug checks
    if hasattr(sys, 'gettrace') and sys.gettrace() is not None:
        os._exit(0)
    
    # Check for debugging tools
    try:
        for proc in psutil.process_iter(['pid', 'name']):
            if any(dbg in proc.info['name'].lower() for dbg in ['gdb', 'lldb', 'ida', 'ollydbg', 'x64dbg']):
                os._exit(0)
    except:
        pass
    
    # Timing-based anti-debug
    start = time.time()
    time.sleep(0.1)
    if time.time() - start > 0.5:  # Debugger slowing down execution
        os._exit(0)
    
    # Memory analysis detection
    if len(gc.get_objects()) > 50000:  # Unusual object count
        os._exit(0)

def {self.generate_obfuscated_name()}():
    # Self-tamper detection
    import inspect
    frame = inspect.currentframe()
    if frame.f_code.co_filename != sys.argv[0]:
        os._exit(0)
    
    # Check file modification time
    try:
        stat = os.stat(__file__)
        if time.time() - stat.st_mtime < 60:  # Modified recently
            os._exit(0)
    except:
        pass

# Execute anti-debug checks in background thread
threading.Thread(target={self.generate_obfuscated_name()}, daemon=True).start()
{self.generate_obfuscated_name()}()
'''
    
    def enhanced_source_cleaning(self, source: str) -> str:
        """Enhanced source code cleaning with AST manipulation"""
        try:
            tree = ast.parse(source)
            cleaner = EnhancedSourceCleaner()
            cleaned_tree = cleaner.visit(tree)
            
            # Remove type hints and annotations
            remover = TypeHintRemover()
            cleaned_tree = remover.visit(cleaned_tree)
            
            return ast.unparse(cleaned_tree)
        except Exception as e:
            # Advanced fallback cleaning
            return self._advanced_regex_cleaning(source)
    
    def _advanced_regex_cleaning(self, source: str) -> str:
        """Advanced regex-based cleaning as fallback"""
        import re
        
        # Remove comments
        source = re.sub(r'#.*', '', source)
        
        # Remove docstrings
        source = re.sub(r'""".*?"""', '', source, flags=re.DOTALL)
        source = re.sub(r"'''.*?'''", '', source, flags=re.DOTALL)
        
        # Remove type hints
        source = re.sub(r':\s*[A-Za-z_][A-Za-z0-9_]*(\[.*?\])?', '', source)
        
        # Remove empty lines
        lines = [line for line in source.split('\n') if line.strip()]
        return '\n'.join(lines)
    
    def calculate_enhanced_hash(self, code: str) -> str:
        """Calculate enhanced hash with salt for anti-tampering"""
        combined = f"{code}{self.master_salt.hex()}{time.time()}"
        return hashlib.sha3_256(combined.encode()).hexdigest()
    
    def create_enhanced_gist(self) -> tuple:
        """Create GitHub Gist with enhanced security"""
        self.gist_filename = f"status_{self.generate_obfuscated_name(16)}.json"
        
        # Create decoy data
        decoy_data = {
            "timestamp": int(time.time()),
            "status": "UNUSED",
            "checksum": hashlib.md5(os.urandom(32)).hexdigest(),
            "version": "2.0.1",
            "metadata": {
                "created": datetime.now().isoformat(),
                "expires": (datetime.now().timestamp() + 86400),  # 24 hours
                "client": "cerberusalt"
            }
        }
        
        gist_data = {
            "description": f"Configuration data - {random.randint(1000, 9999)}",
            "public": False,  # Private gist for better security
            "files": {
                self.gist_filename: {
                    "content": json.dumps(decoy_data, indent=2)
                }
            }
        }
        
        response = requests.post(
            'https://api.github.com/gists',
            headers=self.api_headers,
            json=gist_data,
            timeout=30
        )
        
        if response.status_code == 201:
            gist_info = response.json()
            self.gist_id = gist_info['id']
            return self.gist_id, self.gist_filename
        else:
            raise Exception(f"Failed to create gist: {response.status_code} - {response.text}")
    
    def obfuscate(self, source_code: str) -> str:
        """Enhanced obfuscation pipeline"""
        print("[+] Starting CerberusAlt Advanced Obfuscation...")
        
        # Layer 0: Enhanced preparation
        print("  [*] Layer 0: Enhanced source cleaning and preparation...")
        cleaned_code = self.enhanced_source_cleaning(source_code)
        self.original_hash = self.calculate_enhanced_hash(cleaned_code)
        
        # Layer 1: Advanced AST transformations
        print("  [*] Layer 1: Advanced AST transformations...")
        obfuscated_ast = self.apply_enhanced_ast_transformations(cleaned_code)
        
        # Layer 2: Enhanced encryption & serialization
        print("  [*] Layer 2: AES-256-CBC encryption and serialization...")
        encrypted_data = self.enhanced_encrypt_and_serialize(obfuscated_ast)
        
        # Layer 3: Advanced compression & encoding
        print("  [*] Layer 3: Advanced compression and multi-layer encoding...")
        encoded_payload = self.advanced_compress_and_encode(encrypted_data)
        
        # Layer 4: Create enhanced loader with anti-debug
        print("  [*] Layer 4: Creating enhanced loader with security features...")
        gist_id, gist_filename = self.create_enhanced_gist()
        loader_stub = self.create_enhanced_loader_stub(encoded_payload, gist_id, gist_filename)
        
        # Layer 5: Optional binary compilation
        if self.use_binary:
            print("  [*] Layer 5: Compiling to binary with Nuitka...")
            return self.compile_to_binary(loader_stub)
        
        print("[+] CerberusAlt obfuscation complete!")
        return loader_stub
    
    def apply_enhanced_ast_transformations(self, source_code: str) -> str:
        """Apply enhanced AST transformations with more sophisticated techniques"""
        tree = ast.parse(source_code)
        
        # Apply transformations in optimized sequence
        transformers = [
            EnhancedNameObfuscator(),
            AdvancedStringObfuscator(self.aes_key, self.aes_iv),
            EnhancedIntegerObfuscator(),
            AdvancedControlFlowFlattener(),
            SophisticatedJunkCodeInjector(),
            CallObfuscator(),  # New: Obfuscate function calls
            LoopObfuscator()   # New: Obfuscate loops
        ]
        
        for transformer in transformers:
            tree = transformer.visit(tree)
            ast.fix_missing_locations(tree)  # Fix AST locations
        
        return ast.unparse(tree)
    
    def enhanced_encrypt_and_serialize(self, code: str) -> bytes:
        """Enhanced encryption using AES-256-CBC + XOR + Custom encoding"""
        # Step 1: AES-256-CBC encryption
        cipher = AES.new(self.aes_key, AES.MODE_CBC, self.aes_iv)
        padded_code = pad(code.encode('utf-8'), AES.block_size)
        aes_encrypted = cipher.encrypt(padded_code)
        
        # Step 2: XOR with dynamic key
        self.xor_key = PBKDF2(self.github_token, self.aes_iv, 64, count=50000)
        xor_encrypted = bytes(a ^ b for a, b in zip(aes_encrypted, 
                                                   (self.xor_key * (len(aes_encrypted) // len(self.xor_key) + 1))[:len(aes_encrypted)]))
        
        # Step 3: Marshal with metadata
        metadata = {
            'iv': self.aes_iv,
            'salt': self.master_salt,
            'timestamp': int(time.time()),
            'version': '2.0'
        }
        
        package = {
            'data': xor_encrypted,
            'meta': metadata
        }
        
        marshaled = marshal.dumps(package)
        return marshaled
    
    def advanced_compress_and_encode(self, data: bytes) -> str:
        """Advanced compression and encoding with multiple layers"""
        # Step 1: zlib compression with max level
        compressed = zlib.compress(data, level=9)
        
        # Step 2: Multiple encoding layers with interleaving
        # Layer 1: Base85
        encoded_1 = base64.b85encode(compressed)
        
        # Layer 2: Custom encoding (XOR with pattern)
        pattern = b'CerberusAlt2024'
        pattern_extended = (pattern * (len(encoded_1) // len(pattern) + 1))[:len(encoded_1)]
        encoded_2 = bytes(a ^ b for a, b in zip(encoded_1, pattern_extended))
        
        # Layer 3: Base64
        encoded_3 = base64.b64encode(encoded_2)
        
        # Layer 4: Hexadecimal with scrambling
        hex_encoded = binascii.hexlify(encoded_3).decode()
        
        # Scramble hex string
        scrambled = self._scramble_hex(hex_encoded)
        
        return scrambled
    
    def _scramble_hex(self, hex_string: str) -> str:
        """Scramble hex string for additional obfuscation"""
        chars = list(hex_string)
        # Use deterministic scrambling based on string content
        random.seed(hashlib.md5(hex_string.encode()).hexdigest())
        random.shuffle(chars)
        return ''.join(chars)
    
    def _unscramble_hex(self, scrambled: str) -> str:
        """Unscramble hex string (reverse operation)"""
        # This would be implemented in the loader stub
        pass
    
    def create_enhanced_loader_stub(self, payload: str, gist_id: str, gist_filename: str) -> str:
        """Create enhanced loader stub with advanced security features"""
        # Generate highly obfuscated variable names
        var_names = {
            'payload': self.generate_obfuscated_name(15),
            'gist_id': self.generate_obfuscated_name(15),
            'gist_file': self.generate_obfuscated_name(15),
            'hash': self.generate_obfuscated_name(15),
            'salt': self.generate_obfuscated_name(15),
            'iv': self.generate_obfuscated_name(15),
            'key': self.generate_obfuscated_name(15)
        }
        
        func_names = {
            'check_gist': self.generate_obfuscated_name(20),
            'decode_payload': self.generate_obfuscated_name(20),
            'verify_integrity': self.generate_obfuscated_name(20),
            'anti_debug': self.generate_obfuscated_name(20)
        }
        
        # Anti-debug code
        anti_debug_code = self.apply_anti_debug_checks()
        
        loader_template = f'''# CerberusAlt Protected Code - Advanced Security
import sys,base64,binascii,zlib,marshal,hashlib,requests,os,time,json,threading,random
from Cryptodome.Cipher import AES
from Cryptodome.Protocol.KDF import PBKDF2
from Cryptodome.Util.Padding import unpad

{anti_debug_code}

{var_names['payload']}="{payload}"
{var_names['gist_id']}="{gist_id}"
{var_names['gist_file']}="{gist_filename}"
{var_names['hash']}="{self.original_hash}"
{var_names['salt']}={list(self.master_salt)}
{var_names['iv']}={list(self.aes_iv)}

def {func_names['verify_integrity']}():
    # Enhanced integrity verification
    try:
        import inspect
        frame = inspect.currentframe()
        if frame.f_locals.get('__name__') != '__main__':
            os._exit(0)
    except:
        os._exit(0)

def {func_names['check_gist']}():
    try:
        headers = {{'Authorization': 'token {self.github_token}', 'User-Agent': 'CerberusAlt/2.0'}}
        url = f"https://api.github.com/gists/{{{var_names['gist_id']}}}"
        
        # Multiple requests to detect monitoring
        for i in range(3):
            resp = requests.get(url, headers=headers, timeout=15)
            if resp.status_code != 200:
                os._exit(0)
            time.sleep(random.uniform(0.1, 0.5))
        
        gist_data = resp.json()
        content = json.loads(gist_data["files"][{var_names['gist_file']}]["content"])
        
        # Check expiration
        if time.time() > content.get("metadata", {{}}).get("expires", 0):
            os._exit(0)
        
        if content["status"] != "UNUSED":
            os._exit(0)
        
        # Mark as used with timestamp
        content["status"] = "USED"
        content["used_at"] = time.time()
        content["client_info"] = os.uname().sysname if hasattr(os, 'uname') else 'unknown'
        
        patch_data = {{"files": {{{var_names['gist_file']}: {{"content": json.dumps(content)}}}}}}
        requests.patch(url, headers=headers, json=patch_data, timeout=15)
        
    except Exception as e:
        os._exit(0)

def {func_names['decode_payload']}():
    try:
        # Unscramble hex
        scrambled = {var_names['payload']}
        chars = list(scrambled)
        random.seed(hashlib.md5(scrambled.encode()).hexdigest())
        indices = list(range(len(chars)))
        random.shuffle(indices)
        unscrambled = [''] * len(chars)
        for i, char in enumerate(chars):
            unscrambled[indices[i]] = char
        hex_data = ''.join(unscrambled)
        
        # Reverse encoding layers
        decoded_hex = binascii.unhexlify(hex_data)
        decoded_b64 = base64.b64decode(decoded_hex)
        
        # Reverse custom XOR
        pattern = b'CerberusAlt2024'
        pattern_extended = (pattern * (len(decoded_b64) // len(pattern) + 1))[:len(decoded_b64)]
        decoded_custom = bytes(a ^ b for a, b in zip(decoded_b64, pattern_extended))
        
        decoded_b85 = base64.b85decode(decoded_custom)
        decompressed = zlib.decompress(decoded_b85)
        package = marshal.loads(decompressed)
        
        # Extract data and metadata
        encrypted_data = package['data']
        metadata = package['meta']
        
        # Derive keys
        salt = bytes({var_names['salt']})
        iv = bytes({var_names['iv']})
        aes_key = PBKDF2("{self.github_token}", salt, 32, count=100000)
        xor_key = PBKDF2("{self.github_token}", iv, 64, count=50000)
        
        # Reverse XOR
        xor_expanded = (xor_key * (len(encrypted_data) // len(xor_key) + 1))[:len(encrypted_data)]
        aes_data = bytes(a ^ b for a, b in zip(encrypted_data, xor_expanded))
        
        # AES decryption
        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        padded_code = cipher.decrypt(aes_data)
        code = unpad(padded_code, AES.block_size).decode('utf-8')
        
        # Hash verification
        combined = f"{{code}}{{salt.hex()}}{{metadata['timestamp']}}"
        if hashlib.sha3_256(combined.encode()).hexdigest() != {var_names['hash']}:
            os._exit(0)
        
        return code
    except:
        os._exit(0)

# Execute security checks and payload
{func_names['verify_integrity']}()
{func_names['check_gist']}()
exec({func_names['decode_payload']}())'''
        
        return loader_template
    
    def compile_to_binary(self, loader_code: str) -> str:
        """Compile the obfuscated code to binary using Nuitka"""
        try:
            # Write temporary file
            temp_file = f"temp_cerberusalt_{int(time.time())}.py"
            with open(temp_file, 'w', encoding='utf-8') as f:
                f.write(loader_code)
            
            # Compile with Nuitka
            binary_name = temp_file.replace('.py', '')
            cmd = [
                'nuitka3',
                '--onefile',
                '--remove-output',
                '--no-pyi-file',
                f'--output-filename={binary_name}',
                temp_file
            ]
            
            print("  [*] Compiling with Nuitka...")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            # Clean up temp file
            os.remove(temp_file)
            
            if result.returncode == 0:
                print(f"  [+] Binary compiled successfully: {binary_name}")
                return f"Binary compiled: {binary_name}"
            else:
                print(f"  [-] Nuitka compilation failed: {result.stderr}")
                return loader_code
                
        except Exception as e:
            print(f"  [-] Binary compilation error: {e}")
            return loader_code


# Enhanced AST Transformer Classes

class EnhancedSourceCleaner(ast.NodeTransformer):
    """Enhanced source cleaner with more thorough cleaning"""
    def visit_FunctionDef(self, node):
        # Remove docstrings and annotations
        if (node.body and isinstance(node.body[0], ast.Expr) and 
            isinstance(node.body[0].value, ast.Constant) and 
            isinstance(node.body[0].value.value, str)):
            node.body = node.body[1:]
        
        # Remove type annotations
        node.returns = None
        for arg in node.args.args:
            arg.annotation = None
        
        self.generic_visit(node)
        return node
    
    def visit_ClassDef(self, node):
        # Similar cleaning for classes
        if (node.body and isinstance(node.body[0], ast.Expr) and 
            isinstance(node.body[0].value, ast.Constant) and 
            isinstance(node.body[0].value.value, str)):
            node.body = node.body[1:]
        self.generic_visit(node)
        return node


class TypeHintRemover(ast.NodeTransformer):
    """Remove all type hints and annotations"""
    def visit_arg(self, node):
        node.annotation = None
        return node
    
    def visit_FunctionDef(self, node):
        node.returns = None
        self.generic_visit(node)
        return node
    
    def visit_AnnAssign(self, node):
        # Convert annotated assignments to regular assignments
        return ast.Assign(targets=[node.target], value=node.value)


class EnhancedNameObfuscator(ast.NodeTransformer):
    """Enhanced name obfuscator with better confusion techniques"""
    def __init__(self):
        self.name_mapping = {}
        self.builtin_names = set(dir(__builtins__))
        self.reserved_names = {'self', 'cls', '__init__', '__main__', 'args', 'kwargs'}
        self.counter = 0
        
    def generate_confusing_name(self, original_name: str) -> str:
        if original_name not in self.name_mapping:
            # Use more confusing character combinations
            confusing_chars = ['O', 'o', '0', 'I', 'l', '1', '_']
            base_name = ''.join(random.choices(confusing_chars, k=random.randint(8, 16)))
            
            # Add some pattern to make it even more confusing
            patterns = ['__', '_', '']
            pattern = random.choice(patterns)
            
            self.name_mapping[original_name] = f"{pattern}{base_name}{pattern}"
            self.counter += 1
        
        return self.name_mapping[original_name]
    
    def should_obfuscate(self, name: str) -> bool:
        return (name not in self.builtin_names and 
                name not in self.reserved_names and
                not name.startswith('__') and
                not name.endswith('__') and
                len(name) > 1)
    
    def visit_Name(self, node):
        if self.should_obfuscate(node.id):
            node.id = self.generate_confusing_name(node.id)
        return node
    
    def visit_FunctionDef(self, node):
        if self.should_obfuscate(node.name):
            node.name = self.generate_confusing_name(node.name)
        # Obfuscate arguments
        for arg in node.args.args:
            if self.should_obfuscate(arg.arg):
                arg.arg = self.generate_confusing_name(arg.arg)
        self.generic_visit(node)
        return node
    
    def visit_ClassDef(self, node):
        if self.should_obfuscate(node.name):
            node.name = self.generate_confusing_name(node.name)
        self.generic_visit(node)
        return node


class AdvancedStringObfuscator(ast.NodeTransformer):
    """Advanced string obfuscator with AES-256-CBC"""
    def __init__(self, aes_key: bytes, iv: bytes):
        self.aes_key = aes_key
        self.iv = iv
        self.encrypted_strings = {}
        
    def encrypt_string_advanced(self, text: str) -> str:
        if text in self.encrypted_strings:
            return self.encrypted_strings[text]
        
        # Use AES-256-CBC for string encryption
        cipher = AES.new(self.aes_key, AES.MODE_CBC, self.iv)
        padded_text = pad(text.encode('utf-8'), AES.block_size)
        encrypted = cipher.encrypt(padded_text)
        encoded = base64.b64encode(encrypted).decode()
        
        self.encrypted_strings[text] = encoded
        return encoded
    
    def visit_Constant(self, node):
        if isinstance(node.value, str) and len(node.value) > 1:
            # Skip very short strings and special values
            if node.value in ['\n', '\t', ' ', '', '__main__']:
                return node
                
            encrypted = self.encrypt_string_advanced(node.value)
            # Replace with a complex decryption expression
            return ast.Call(
                func=ast.Attribute(
                    value=ast.Name(id='O0O0o0O0', ctx=ast.Load()),
                    attr='decrypt',
                    ctx=ast.Load()
                ),
                args=[ast.Constant(value=encrypted)],
                keywords=[]
            )
        return node


class EnhancedIntegerObfuscator(ast.NodeTransformer):
    """Enhanced integer obfuscator with more complex expressions"""
    def visit_Constant(self, node):
        if isinstance(node.value, int) and 0 < abs(node.value) < 100000:
            # Create very complex mathematical expressions
            techniques = [
                self._create_bitwise_expression,
                self._create_arithmetic_expression,
                self._create_power_expression,
                self._create_factorial_expression
            ]
            
            technique = random.choice(techniques)
            result = technique(node.value)
            return result if result else node
        
        return node
    
    def _create_bitwise_expression(self, value: int) -> ast.expr:
        """Create complex bitwise expression"""
        # Example: ((value << 2) >> 1) ^ (value & 0xFF)
        return ast.BinOp(
            left=ast.BinOp(
                left=ast.BinOp(
                    left=ast.Constant(value=value),
                    op=ast.LShift(),
                    right=ast.Constant(value=2)
                ),
                op=ast.RShift(),
                right=ast.Constant(value=1)
            ),
            op=ast.BitXor(),
            right=ast.BinOp(
                left=ast.Constant(value=value),
                op=ast.BitAnd(),
                right=ast.Constant(value=0xFF)
            )
        )
    
    def _create_arithmetic_expression(self, value: int) -> ast.expr:
        """Create complex arithmetic expression"""
        base1 = random.randint(1, 50)
        base2 = random.randint(1, 50)
        # (value + base1) * base2 - base1 * base2
        return ast.BinOp(
            left=ast.BinOp(
                left=ast.BinOp(
                    left=ast.Constant(value=value),
                    op=ast.Add(),
                    right=ast.Constant(value=base1)
                ),
                op=ast.Mult(),
                right=ast.Constant(value=base2)
            ),
            op=ast.Sub(),
            right=ast.BinOp(
                left=ast.Constant(value=base1),
                op=ast.Mult(),
                right=ast.Constant(value=base2)
            )
        )
    
    def _create_power_expression(self, value: int) -> ast.expr:
        """Create power-based expression"""
        if value < 1000:  # Avoid huge numbers
            # value = sqrt(value^2)
            return ast.Call(
                func=ast.Name(id='int', ctx=ast.Load()),
                args=[
                    ast.Call(
                        func=ast.Attribute(
                            value=ast.Name(id='math', ctx=ast.Load()),
                            attr='sqrt',
                            ctx=ast.Load()
                        ),
                        args=[
                            ast.BinOp(
                                left=ast.Constant(value=value),
                                op=ast.Pow(),
                                right=ast.Constant(value=2)
                            )
                        ],
                        keywords=[]
                    )
                ],
                keywords=[]
            )
        return None
    
    def _create_factorial_expression(self, value: int) -> ast.expr:
        """Create factorial-based expression (for small values)"""
        if value <= 10:
            # Use sum of range
            return ast.Call(
                func=ast.Name(id='sum', ctx=ast.Load()),
                args=[
                    ast.Call(
                        func=ast.Name(id='range', ctx=ast.Load()),
                        args=[
                            ast.Constant(value=1),
                            ast.Constant(value=value + 1)
                        ],
                        keywords=[]
                    )
                ],
                keywords=[]
            )
        return None


class AdvancedControlFlowFlattener(ast.NodeTransformer):
    """Advanced control flow flattener with more sophisticated state machines"""
    def __init__(self):
        self.state_counter = 0
        self.complexity_threshold = 4
        
    def visit_FunctionDef(self, node):
        if len(node.body) > self.complexity_threshold:
            # Apply more sophisticated flattening
            flattened = self.create_advanced_state_machine(node.body)
            node.body = flattened
        self.generic_visit(node)
        return node
    
    def create_advanced_state_machine(self, body: List[ast.stmt]) -> List[ast.stmt]:
        """Create advanced state machine with nested states and randomization"""
        state_var = f"__state_{self.state_counter}__"
        jump_table_var = f"__jumps_{self.state_counter}__"
        self.state_counter += 1
        
        # Create randomized jump table
        states = list(range(len(body)))
        random.shuffle(states)
        
        # Initialize state variables
        init_statements = [
            ast.Assign(
                targets=[ast.Name(id=state_var, ctx=ast.Store())],
                value=ast.Constant(value=states[0])
            ),
            ast.Assign(
                targets=[ast.Name(id=jump_table_var, ctx=ast.Store())],
                value=ast.List(elts=[ast.Constant(value=s) for s in states], ctx=ast.Load())
            )
        ]
        
        # Create state cases with randomized order
        case_dict = {}
        for i, stmt in enumerate(body):
            state_id = states[i]
            next_state = states[i + 1] if i + 1 < len(states) else -1
            
            case_body = [
                stmt,
                ast.Assign(
                    targets=[ast.Name(id=state_var, ctx=ast.Store())],
                    value=ast.Constant(value=next_state) if next_state != -1 
                          else ast.Constant(value=-1)
                )
            ]
            case_dict[state_id] = case_body
        
        # Build if-elif chain
        current_if = None
        for state_id in sorted(case_dict.keys()):
            case_test = ast.Compare(
                left=ast.Name(id=state_var, ctx=ast.Load()),
                ops=[ast.Eq()],
                comparators=[ast.Constant(value=state_id)]
            )
            
            if current_if is None:
                current_if = ast.If(test=case_test, body=case_dict[state_id], orelse=[])
                root_if = current_if
            else:
                new_if = ast.If(test=case_test, body=case_dict[state_id], orelse=[])
                current_if.orelse = [new_if]
                current_if = new_if
        
        # Create main loop with exit condition
        exit_condition = ast.Compare(
            left=ast.Name(id=state_var, ctx=ast.Load()),
            ops=[ast.Lt()],
            comparators=[ast.Constant(value=0)]
        )
        
        main_loop = ast.While(
            test=ast.UnaryOp(op=ast.Not(), operand=exit_condition),
            body=[root_if],
            orelse=[]
        )
        
        return init_statements + [main_loop]


class SophisticatedJunkCodeInjector(ast.NodeTransformer):
    """Sophisticated junk code injector with realistic-looking dead code"""
    def visit_FunctionDef(self, node):
        # Inject sophisticated junk code
        junk_snippets = self.create_sophisticated_junk()
        
        # Insert at random positions
        for _ in range(random.randint(2, 5)):
            pos = random.randint(0, len(node.body))
            snippet = random.choice(junk_snippets)
            node.body.insert(pos, snippet)
        
        self.generic_visit(node)
        return node
    
    def create_sophisticated_junk(self) -> List[ast.stmt]:
        """Create sophisticated junk code that looks realistic"""
        return [
            # Fake calculation that does nothing
            ast.If(
                test=ast.Compare(
                    left=ast.Call(
                        func=ast.Name(id='hash', ctx=ast.Load()),
                        args=[ast.Constant(value="dummy")],
                        keywords=[]
                    ),
                    ops=[ast.Mod()],
                    comparators=[ast.Constant(value=2)]
                ),
                body=[
                    ast.Assign(
                        targets=[ast.Name(id=f'_tmp_{random.randint(1000, 9999)}', ctx=ast.Store())],
                        value=ast.Call(
                            func=ast.Name(id='sum', ctx=ast.Load()),
                            args=[
                                ast.Call(
                                    func=ast.Name(id='range', ctx=ast.Load()),
                                    args=[ast.Constant(value=random.randint(1, 100))],
                                    keywords=[]
                                )
                            ],
                            keywords=[]
                        )
                    )
                ],
                orelse=[]
            ),
            
            # Fake try-except that never executes
            ast.Try(
                body=[
                    ast.If(
                        test=ast.Constant(value=False),
                        body=[
                            ast.Raise(
                                exc=ast.Call(
                                    func=ast.Name(id='ValueError', ctx=ast.Load()),
                                    args=[ast.Constant(value="This never happens")],
                                    keywords=[]
                                ),
                                cause=None
                            )
                        ],
                        orelse=[]
                    )
                ],
                handlers=[
                    ast.ExceptHandler(
                        type=ast.Name(id='ValueError', ctx=ast.Load()),
                        name='e',
                        body=[ast.Pass()]
                    )
                ],
                orelse=[],
                finalbody=[]
            ),
            
            # Complex opaque predicate
            ast.If(
                test=ast.Compare(
                    left=ast.BinOp(
                        left=ast.Call(
                            func=ast.Name(id='len', ctx=ast.Load()),
                            args=[ast.Constant(value="constant")],
                            keywords=[]
                        ),
                        op=ast.Mult(),
                        right=ast.Constant(value=7)
                    ),
                    ops=[ast.Gt()],
                    comparators=[ast.Constant(value=0)]
                ),
                body=[
                    ast.For(
                        target=ast.Name(id=f'_i_{random.randint(100, 999)}', ctx=ast.Store()),
                        iter=ast.Call(
                            func=ast.Name(id='range', ctx=ast.Load()),
                            args=[ast.Constant(value=1)],
                            keywords=[]
                        ),
                        body=[ast.Pass()],
                        orelse=[]
                    )
                ],
                orelse=[]
            )
        ]


class CallObfuscator(ast.NodeTransformer):
    """Obfuscate function calls"""
    def visit_Call(self, node):
        # Add some complexity to function calls
        if isinstance(node.func, ast.Name) and random.random() < 0.3:
            # Wrap simple calls in getattr for obfuscation
            return ast.Call(
                func=ast.Name(id='getattr', ctx=ast.Load()),
                args=[
                    ast.Name(id='__builtins__', ctx=ast.Load()),
                    ast.Constant(value=node.func.id)
                ] + node.args,
                keywords=node.keywords
            )
        
        self.generic_visit(node)
        return node


class LoopObfuscator(ast.NodeTransformer):
    """Obfuscate loops with additional complexity"""
    def visit_For(self, node):
        # Add complexity to for loops
        if random.random() < 0.4:
            # Add a dummy variable
            dummy_var = f'_loop_dummy_{random.randint(100, 999)}'
            node.body.insert(0, ast.Assign(
                targets=[ast.Name(id=dummy_var, ctx=ast.Store())],
                value=ast.Constant(value=0)
            ))
        
        self.generic_visit(node)
        return node


def main():
    parser = argparse.ArgumentParser(description='CerberusAlt - Advanced Python Code Obfuscator')
    parser.add_argument('-i', '--input', required=True, help='Input Python file to obfuscate')
    parser.add_argument('-o', '--output', required=True, help='Output file for obfuscated code')
    parser.add_argument('--token', required=True, help='GitHub Personal Access Token')
    parser.add_argument('--binary', action='store_true', help='Compile to binary using Nuitka')
    parser.add_argument('--no-debug-checks', action='store_true', help='Disable anti-debug mechanisms')
    
    args = parser.parse_args()
    
    try:
        # Read input file
        with open(args.input, 'r', encoding='utf-8') as f:
            source_code = f.read()
        
        # Initialize advanced obfuscator
        obfuscator = CerberusAltObfuscator(args.token, args.binary)
        if args.no_debug_checks:
            obfuscator.debug_checks = False
        
        # Perform advanced obfuscation
        obfuscated_code = obfuscator.obfuscate(source_code)
        
        # Write output
        if not args.binary or "Binary compiled:" not in obfuscated_code:
            with open(args.output, 'w', encoding='utf-8') as f:
                f.write(obfuscated_code)
            print(f"[+] Successfully obfuscated {args.input} -> {args.output}")
        
        print(f"[+] GitHub Gist ID: {obfuscator.gist_id}")
        print(f"[+] Status file: {obfuscator.gist_filename}")
        print("[!] WARNING: The obfuscated file can only be executed ONCE!")
        print("[!] Enhanced security features:")
        print("    - AES-256-CBC encryption")
        print("    - Advanced anti-debug mechanisms")
        print("    - Self-tamper detection")
        print("    - Sophisticated control flow flattening")
        if args.binary:
            print("    - Binary compilation with Nuitka")
        
    except Exception as e:
        print(f"[-] Error: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main() 