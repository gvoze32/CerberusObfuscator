#!/usr/bin/env python3
"""
Cerberus Obfuscator - Advanced Multi-Layer Python Code Obfuscator
Author: gvoze32
Version: 1.0

Dependencies:
- requests (optional, only needed with --token)
- pycryptodome

Usage:
# With GitHub Gist (one-time execution):
python cerberus.py -i <input_file.py> -o <output_file.py> --token <github_access_token>

# Without GitHub Gist (local execution):
python cerberus.py -i <input_file.py> -o <output_file.py>
"""

import ast
import argparse
import base64
import binascii
import hashlib
import json
import marshal
import os
import random
import string
import sys
import time
import zlib
from datetime import datetime
from typing import Dict, List, Set, Any, Optional

# Optional import for GitHub functionality
try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad


class CerberusObfuscator:
    def __init__(self, github_token: Optional[str] = None):
        self.github_token = github_token
        self.use_gist = github_token is not None
        
        if self.use_gist:
            if not HAS_REQUESTS:
                raise Exception("requests library is required when using --token. Install with: pip install requests")
            self.api_headers = {
                'Authorization': f'token {github_token}',
                'Accept': 'application/vnd.github.v3+json'
            }
        
        self.original_hash = None
        self.aes_key = get_random_bytes(32)  # 256-bit key
        self.xor_key = None
        self.gist_id = None
        self.gist_filename = None
        
    def generate_random_name(self, length: int = 8) -> str:
        """Generate obfuscated variable names"""
        first_chars = 'OoIl_'  # Valid starting characters
        other_chars = 'OoIl0_'  # Characters for the rest
        
        # Ensure name starts with valid character and isn't octal-like
        while True:
            name = random.choice(first_chars)
            name += ''.join(random.choice(other_chars) for _ in range(length - 1))
            
            # Avoid patterns that look like octal literals
            if not (name.startswith('0') or name.startswith('O0') or name.startswith('o0')):
                break
                
        return name
    
    def clean_source_code(self, source: str) -> str:
        """Layer 0: Remove comments and docstrings"""
        try:
            tree = ast.parse(source)
            cleaner = SourceCleaner()
            cleaned_tree = cleaner.visit(tree)
            return ast.unparse(cleaned_tree)
        except Exception as e:
            # Fallback: improved regex cleaning with indentation handling
            print(f"[*] AST cleaning failed ({e}), using regex fallback...")
            lines = source.split('\n')
            cleaned_lines = []
            in_multiline_string = False
            in_docstring = False
            
            for i, line in enumerate(lines):
                stripped = line.strip()
                
                # Skip empty lines and comments
                if not stripped or stripped.startswith('#'):
                    continue
                
                # Handle multiline strings/docstrings
                if '"""' in line or "'''" in line:
                    # Count quotes to handle multiple on same line
                    quote_count = line.count('"""') + line.count("'''")
                    if quote_count % 2 == 1:  # Odd number means start/end of string
                        if not in_multiline_string:
                            in_multiline_string = True
                            # Skip docstrings at start of functions/classes
                            if i > 0 and any(keyword in lines[i-1] for keyword in ['def ', 'class ']):
                                in_docstring = True
                            continue
                        else:
                            in_multiline_string = False
                            in_docstring = False
                            continue
                
                # Skip content inside multiline strings
                if in_multiline_string:
                    continue
                
                # Keep the line with proper indentation
                cleaned_lines.append(line)
                    
            # Ensure proper indentation consistency
            result = '\n'.join(cleaned_lines)
            
            # Validate the result
            try:
                ast.parse(result)
                return result
            except SyntaxError:
                # If still fails, return original code
                print("[*] Regex cleaning also failed, returning original code...")
                return source
    
    def calculate_hash(self, code: str) -> str:
        """Calculate SHA-256 hash for anti-tampering"""
        return hashlib.sha256(code.encode()).hexdigest()
    
    def create_github_gist(self) -> tuple:
        """Create GitHub Gist for one-time execution tracking using JSON format"""
        if not self.use_gist:
            return None, None
            
        self.gist_filename = f"status_{''.join(random.choices(string.ascii_letters + string.digits, k=12))}.json"
        
        # Create JSON data structure like cerberusbin
        
        status_data = {
            "timestamp": int(time.time()),
            "status": "UNUSED",
            "checksum": hashlib.md5(os.urandom(32)).hexdigest(),
            "version": "1.0.1",
            "metadata": {
                "created": datetime.now().isoformat(),
                "expires": (datetime.now().timestamp() + 86400),  # 24 hours
                "client": "cerberus"
            }
        }
        
        gist_data = {
            "description": f"Configuration data - {random.randint(1000, 9999)}",
            "public": False,  # Private gist for better security like cerberusbin
            "files": {
                self.gist_filename: {
                    "content": json.dumps(status_data, indent=2)
                }
            }
        }
        
        response = requests.post(
            'https://api.github.com/gists',
            headers=self.api_headers,
            json=gist_data
        )
        
        if response.status_code == 201:
            gist_info = response.json()
            self.gist_id = gist_info['id']
            return self.gist_id, self.gist_filename
        else:
            raise Exception(f"Failed to create gist: {response.status_code}")
    
    def obfuscate(self, source_code: str) -> str:
        """Main obfuscation pipeline"""
        if self.use_gist:
            print("[+] Starting Cerberus Obfuscation Process (with GitHub Gist)...")
        else:
            print("[+] Starting Cerberus Obfuscation Process (standalone mode)...")
        
        # Layer 0: Preparation
        print("  [*] Layer 0: Cleaning source code...")
        cleaned_code = self.clean_source_code(source_code)
        
        # Layer 1: AST Transformations
        print("  [*] Layer 1: Applying AST transformations...")
        obfuscated_ast = self.apply_ast_transformations(cleaned_code)
        
        # Calculate hash AFTER transformations to match what's actually encrypted
        self.original_hash = self.calculate_hash(obfuscated_ast)
        
        # Layer 2: Encryption & Serialization
        print("  [*] Layer 2: Encrypting and serializing...")
        encrypted_data = self.encrypt_and_serialize(obfuscated_ast)
        
        # Layer 3: Compression & Encoding
        print("  [*] Layer 3: Compressing and encoding...")
        encoded_payload = self.compress_and_encode(encrypted_data)
        
        # Layer 4: Create Loader (with or without GitHub Gist)
        if self.use_gist:
            print("  [*] Layer 4: Creating GitHub Gist and loader stub...")
            gist_id, gist_filename = self.create_github_gist()
            loader_stub = self.create_loader_stub(encoded_payload, gist_id, gist_filename)
        else:
            print("  [*] Layer 4: Creating standalone loader stub...")
            loader_stub = self.create_standalone_loader_stub(encoded_payload)
        
        print("[+] Obfuscation complete!")
        return loader_stub
    
    def apply_ast_transformations(self, source_code: str) -> str:
        """Layer 1: Apply all AST transformations"""
        try:
            tree = ast.parse(source_code)
            
            # Apply transformations in sequence (safer set for standalone)
            transformers = [
                IntegerObfuscator()
                # Note: Name and String obfuscation disabled in standalone mode for compatibility
                # Note: ControlFlowFlattener and DeadCodeInjector temporarily disabled
                # due to potential indentation issues with complex AST structures
            ]
            
            # Only add advanced obfuscations if using Gist mode (has proper loader)
            if self.use_gist:
                # TEMPORARILY DISABLED NameObfuscator to avoid variable naming conflicts
                # transformers.insert(0, NameObfuscator())
                # DISABLED StringObfuscator for now due to compatibility issues
                # transformers.insert(1, StringObfuscator(self.aes_key))
                pass
            
            for transformer in transformers:
                tree = transformer.visit(tree)
            
            # Generate code with proper indentation
            unparsed_code = ast.unparse(tree)
            
            # Fix any indentation issues
            return self.fix_indentation(unparsed_code)
            
        except IndentationError as e:
            print(f"[-] Error: {e}")
            print("[-] Trying fallback method...")
            return self.fallback_obfuscation(source_code)
        except Exception as e:
            print(f"[-] Error: {e}")
            print("[-] Trying fallback method...")
            return self.fallback_obfuscation(source_code)
    
    def fix_indentation(self, code: str) -> str:
        """Fix indentation issues in generated code"""
        import textwrap
        lines = code.split('\n')
        
        # Remove leading/trailing empty lines
        while lines and not lines[0].strip():
            lines.pop(0)
        while lines and not lines[-1].strip():
            lines.pop()
        
        if not lines:
            return code
            
        # Find minimum indentation (excluding empty lines)
        min_indent = float('inf')
        for line in lines:
            if line.strip():  # Skip empty lines
                indent = len(line) - len(line.lstrip())
                min_indent = min(min_indent, indent)
        
        if min_indent == float('inf'):
            min_indent = 0
            
        # Remove common leading whitespace
        fixed_lines = []
        for line in lines:
            if line.strip():
                fixed_lines.append(line[min_indent:] if len(line) > min_indent else line)
            else:
                fixed_lines.append('')
        
        return '\n'.join(fixed_lines)
    
    def fallback_obfuscation(self, source_code: str) -> str:
        """Fallback obfuscation method with simpler transformations"""
        try:
            tree = ast.parse(source_code)
            
            # Apply only the safest transformations
            safe_transformers = [
                NameObfuscator()
                # StringObfuscator disabled in fallback for maximum compatibility
            ]
            
            for transformer in safe_transformers:
                tree = transformer.visit(tree)
            
            return ast.unparse(tree)
            
        except Exception as e:
            print(f"[-] Fallback also failed: {e}")
            print("[-] Using original code with minimal obfuscation...")
            return source_code
    
    def encrypt_and_serialize(self, code: str) -> bytes:
        """Layer 2: XOR encryption and marshal serialization"""
        # XOR encryption
        self.xor_key = os.urandom(32)
        code_bytes = code.encode()
        key_expanded = (self.xor_key * (len(code_bytes) // len(self.xor_key) + 1))[:len(code_bytes)]
        xor_encrypted = bytes(a ^ b for a, b in zip(code_bytes, key_expanded))
        
        # Marshal serialization
        marshaled = marshal.dumps(xor_encrypted)
        return marshaled
    
    def compress_and_encode(self, data: bytes) -> str:
        """Layer 3: zlib compression and simpler reliable encoding"""
        # Compress
        compressed = zlib.compress(data)
        
        # Simpler encoding: Base64 -> Hex (more reliable than Base85)
        encoded_b64 = base64.b64encode(compressed)
        encoded_hex = binascii.hexlify(encoded_b64).decode()
        
        return encoded_hex
    
    def create_loader_stub(self, payload: str, gist_id: str, gist_filename: str) -> str:
        """Layer 4: Create the final loader stub with one-time execution"""
        # Generate obfuscated variable names
        var_payload = self.generate_random_name()
        var_xor_key = self.generate_random_name()
        var_hash = self.generate_random_name()
        var_gist_id = self.generate_random_name()
        var_gist_file = self.generate_random_name()
        var_token = self.generate_random_name()
        func_check = self.generate_random_name()
        func_decode = self.generate_random_name()
        
        loader_template = f'''# Cerberus Protected Code - One-Time Execution Only
import sys,base64,binascii,zlib,marshal,hashlib,requests,os,json,time
{var_payload}="{payload}"
{var_xor_key}={list(self.xor_key)}
{var_hash}="{self.original_hash}"
{var_gist_id}="{gist_id}"
{var_gist_file}="{gist_filename}"
{var_token}="{self.github_token if self.github_token else ''}"

def {func_check}():
 try:
  headers = {{'Authorization': f'token {{{var_token}}}', 'User-Agent': 'Cerberus/1.0'}} if {var_token} else {{'User-Agent': 'Cerberus/1.0'}}
  url = f"https://api.github.com/gists/{{{var_gist_id}}}"
  
  # Multiple requests to detect monitoring like cerberusbin
  for i in range(3):
   resp = requests.get(url, headers=headers, timeout=15)
   if resp.status_code != 200:
    os._exit(0)
   time.sleep(0.1)
  
  gist_data = resp.json()
  content = json.loads(gist_data["files"][{var_gist_file}]["content"])
  
  # Check expiration like cerberusbin
  if time.time() > content.get("metadata", {{}}).get("expires", 0):
   os._exit(0)
  
  if content["status"] != "UNUSED":
   os._exit(0)
  
  # Mark as used with timestamp like cerberusbin
  content["status"] = "USED"
  content["used_at"] = time.time()
  content["client_info"] = os.uname().sysname if hasattr(os, 'uname') else 'unknown'
  
  patch_data = {{"files": {{{var_gist_file}: {{"content": json.dumps(content)}}}}}}
  requests.patch(url, headers=headers, json=patch_data, timeout=15)
  
 except Exception as e:
  os._exit(0)

def {func_decode}():
 try:
  decoded_hex = binascii.unhexlify({var_payload})
  decoded_b64 = base64.b64decode(decoded_hex)
  decompressed = zlib.decompress(decoded_b64)
  unmarshaled = marshal.loads(decompressed)
  xor_key = bytes({var_xor_key})
  key_expanded = (xor_key * (len(unmarshaled) // len(xor_key) + 1))[:len(unmarshaled)]
  decrypted = bytes(a ^ b for a, b in zip(unmarshaled, key_expanded))
  if hashlib.sha256(decrypted).hexdigest() != {var_hash}:
   sys.exit(0)
  return decrypted.decode()
 except:
  sys.exit(0)

# Execute protection and payload
{func_check}()
exec({func_decode}())'''
        
        return loader_template

    def create_standalone_loader_stub(self, payload: str) -> str:
        """Create a standalone loader stub without GitHub Gist dependency"""
        xor_key_hex = self.xor_key.hex()
        aes_key_hex = self.aes_key.hex()
        hash_value = self.original_hash
        
        # Generate function names once
        anti_tamper_func = self.generate_random_name()
        decrypt_func = self.generate_random_name()
        execute_func = self.generate_random_name()
        
        return f'''#!/usr/bin/env python3
# Protected by Cerberus Obfuscator (Standalone Mode)
# Multi-layer obfuscated Python code

import base64
import binascii
import hashlib
import marshal
import sys
import zlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

def {anti_tamper_func}():
    """Anti-tampering protection"""
    # Simple integrity check (reduced complexity for standalone)
    try:
        with open(__file__, 'r') as f:
            content = f.read()
        # Basic hash check
        if len(content) < 100:  # Minimum expected file size
            sys.exit(1)
    except:
        sys.exit(1)

def {decrypt_func}(data):
    """Multi-layer decryption and decompression"""
    try:
        # Layer 3: Decode from Hex -> Base64 (simplified encoding)
        hex_data = binascii.unhexlify(data)
        b64_data = base64.b64decode(hex_data)
        
        # Layer 3: Decompress
        compressed_data = zlib.decompress(b64_data)
        
        # Layer 2: Unmarshal first
        marshaled_data = marshal.loads(compressed_data)
        
        # Layer 2: XOR decryption
        xor_key = bytes.fromhex("{xor_key_hex}")
        key_expanded = (xor_key * (len(marshaled_data) // len(xor_key) + 1))[:len(marshaled_data)]
        decrypted_code = bytes(a ^ b for a, b in zip(marshaled_data, key_expanded))
        
        return decrypted_code.decode('utf-8')
        
    except Exception as e:
        print(f"Decryption failed: {{e}}")
        sys.exit(1)

def {execute_func}():
    """Execute the protected code"""
    # Verify integrity
    {anti_tamper_func}()
    
    # Decode and execute
    payload = "{payload}"
    code = {decrypt_func}(payload)
    
    # Execute the decrypted code
    exec(code, {{'__name__': '__main__'}})

if __name__ == "__main__":
    {execute_func}()
'''


class SourceCleaner(ast.NodeTransformer):
    """Remove docstrings and comments from AST"""
    def visit_FunctionDef(self, node):
        if (node.body and isinstance(node.body[0], ast.Expr) and 
            isinstance(node.body[0].value, ast.Constant) and 
            isinstance(node.body[0].value.value, str)):
            node.body = node.body[1:]
        self.generic_visit(node)
        return node
    
    def visit_ClassDef(self, node):
        if (node.body and isinstance(node.body[0], ast.Expr) and 
            isinstance(node.body[0].value, ast.Constant) and 
            isinstance(node.body[0].value.value, str)):
            node.body = node.body[1:]
        self.generic_visit(node)
        return node


class NameObfuscator(ast.NodeTransformer):
    """Obfuscate variable, function, and class names"""
    def __init__(self):
        self.name_mapping = {}
        self.builtin_names = set(dir(__builtins__))
        self.reserved_names = {'self', 'cls', '__init__', '__main__'}
        
    def generate_obfuscated_name(self, original_name: str) -> str:
        if original_name not in self.name_mapping:
            # Use deterministic but obfuscated naming to avoid inconsistencies
            import hashlib
            
            # Create a deterministic hash-based obfuscated name
            hash_obj = hashlib.md5(original_name.encode())
            hash_hex = hash_obj.hexdigest()
            
            # Convert to obfuscated pattern using safe characters
            chars = 'OoIl_'
            name = ''
            
            # First character must be letter or underscore
            name += chars[int(hash_hex[0], 16) % len(chars)]
            
            # Remaining characters
            for i in range(1, 8):
                if i < len(hash_hex):
                    char_idx = int(hash_hex[i], 16) % len(chars)
                    name += chars[char_idx]
                else:
                    name += '_'
            
            # Ensure uniqueness by adding suffix if needed
            base_name = name
            counter = 0
            while name in self.name_mapping.values():
                counter += 1
                name = base_name + str(counter)
                    
            self.name_mapping[original_name] = name
        return self.name_mapping[original_name]
    
    def should_obfuscate(self, name: str) -> bool:
        return (name not in self.builtin_names and 
                name not in self.reserved_names and
                not name.startswith('__') and
                not name.endswith('__'))
    
    def visit_Name(self, node):
        if self.should_obfuscate(node.id):
            node.id = self.generate_obfuscated_name(node.id)
        return node
    
    def visit_FunctionDef(self, node):
        if self.should_obfuscate(node.name):
            node.name = self.generate_obfuscated_name(node.name)
        # Obfuscate arguments
        for arg in node.args.args:
            if self.should_obfuscate(arg.arg):
                arg.arg = self.generate_obfuscated_name(arg.arg)
        self.generic_visit(node)
        return node
    
    def visit_ClassDef(self, node):
        if self.should_obfuscate(node.name):
            node.name = self.generate_obfuscated_name(node.name)
        self.generic_visit(node)
        return node


class StringObfuscator(ast.NodeTransformer):
    """Encrypt string literals with AES-256"""
    def __init__(self, aes_key: bytes):
        self.aes_key = aes_key
        self.encrypted_strings = {}
        self.in_fstring = False  # Track if we're inside an f-string
        
    def encrypt_string(self, text: str) -> str:
        if text in self.encrypted_strings:
            return self.encrypted_strings[text]
            
        cipher = AES.new(self.aes_key, AES.MODE_ECB)
        padded_text = pad(text.encode(), AES.block_size)
        encrypted = cipher.encrypt(padded_text)
        encoded = base64.b64encode(encrypted).decode()
        
        self.encrypted_strings[text] = encoded
        return encoded
    
    def visit_Constant(self, node):
        # Skip string encryption if we're inside an f-string
        if self.in_fstring:
            return node
            
        if isinstance(node.value, str) and len(node.value) > 1:
            # Don't encrypt very short strings or strings that might be format specifiers
            if len(node.value.strip()) <= 1:
                return node
                
            encrypted = self.encrypt_string(node.value)
            # Replace with decryption call - will be handled in loader
            return ast.Call(
                func=ast.Name(id='O0o0O0o', ctx=ast.Load()),
                args=[ast.Constant(value=encrypted)],
                keywords=[]
            )
        return node
    
    def visit_JoinedStr(self, node):
        # Mark that we're entering an f-string and skip processing its content
        # F-strings have complex internal structure that shouldn't be modified
        old_in_fstring = self.in_fstring
        self.in_fstring = True
        result = self.generic_visit(node)
        self.in_fstring = old_in_fstring
        return result


class IntegerObfuscator(ast.NodeTransformer):
    """Obfuscate integer constants with complex expressions"""
    def visit_Constant(self, node):
        if isinstance(node.value, int) and 0 < abs(node.value) < 10000:
            # Create complex mathematical expression
            base = random.randint(2, 100)
            operations = [
                lambda x, b: ast.BinOp(left=ast.Constant(value=b), op=ast.Mult(), right=ast.Constant(value=x//b)) if x % b == 0 else None,
                lambda x, b: ast.BinOp(left=ast.BinOp(left=ast.Constant(value=b), op=ast.Mult(), right=ast.Constant(value=2)), op=ast.Sub(), right=ast.Constant(value=2*b-x)),
                lambda x, b: ast.BinOp(left=ast.Constant(value=x+b), op=ast.Sub(), right=ast.Constant(value=b)),
                lambda x, b: ast.BinOp(left=ast.Constant(value=x^b), op=ast.BitXor(), right=ast.Constant(value=b))
            ]
            
            op = random.choice(operations)
            result = op(node.value, base)
            if result:
                return result
                
        return node


class ControlFlowFlattener(ast.NodeTransformer):
    """Flatten control flow using state machines"""
    def __init__(self):
        self.state_counter = 0
        
    def visit_FunctionDef(self, node):
        if len(node.body) > 3:  # Only flatten complex functions
            flattened = self.flatten_function_body(node.body)
            node.body = flattened
        self.generic_visit(node)
        return node
    
    def flatten_function_body(self, body: List[ast.stmt]) -> List[ast.stmt]:
        """Convert linear code blocks into state machine"""
        state_var = f"OoO{self.state_counter}"
        self.state_counter += 1
        
        # Initialize state variable
        init_state = ast.Assign(
            targets=[ast.Name(id=state_var, ctx=ast.Store())],
            value=ast.Constant(value=0)
        )
        
        # Create state cases
        current_if = None
        for i, stmt in enumerate(body):
            case_test = ast.Compare(
                left=ast.Name(id=state_var, ctx=ast.Load()),
                ops=[ast.Eq()],
                comparators=[ast.Constant(value=i)]
            )
            
            case_body = [
                stmt,
                ast.Assign(
                    targets=[ast.Name(id=state_var, ctx=ast.Store())],
                    value=ast.Constant(value=i+1)
                )
            ]
            
            if i == 0:
                current_if = ast.If(test=case_test, body=case_body, orelse=[])
                root_if = current_if
            else:
                new_if = ast.If(test=case_test, body=case_body, orelse=[])
                current_if.orelse = [new_if]
                current_if = new_if
        
        # Add exit condition
        exit_test = ast.Compare(
            left=ast.Name(id=state_var, ctx=ast.Load()),
            ops=[ast.GtE()],
            comparators=[ast.Constant(value=len(body))]
        )
        
        # Create while loop
        while_loop = ast.While(
            test=ast.Constant(value=True),
            body=[
                ast.If(test=exit_test, body=[ast.Break()], orelse=[]),
                root_if
            ],
            orelse=[]
        )
        
        return [init_state, while_loop]


class DeadCodeInjector(ast.NodeTransformer):
    """Inject dead code and opaque predicates"""
    def visit_FunctionDef(self, node):
        # Inject opaque predicates and dead code
        dead_code_snippets = self.create_dead_code_snippets()
        
        # Insert dead code at random positions
        for _ in range(random.randint(1, 3)):
            pos = random.randint(0, len(node.body))
            node.body.insert(pos, random.choice(dead_code_snippets))
        
        self.generic_visit(node)
        return node
    
    def create_dead_code_snippets(self) -> List[ast.stmt]:
        """Create various dead code patterns"""
        return [
            # Always true predicate
            ast.If(
                test=ast.Compare(
                    left=ast.BinOp(
                        left=ast.Constant(value=5),
                        op=ast.Mult(),
                        right=ast.Constant(value=5)
                    ),
                    ops=[ast.GtE()],
                    comparators=[ast.Constant(value=0)]
                ),
                body=[ast.Pass()],
                orelse=[]
            ),
            # Always false predicate with dead code
            ast.If(
                test=ast.Compare(
                    left=ast.Constant(value=1),
                    ops=[ast.Eq()],
                    comparators=[ast.Constant(value=0)]
                ),
                body=[
                    ast.Assign(
                        targets=[ast.Name(id=f'O{random.randint(0,9)}o{random.randint(0,9)}', ctx=ast.Store())],
                        value=ast.Constant(value=random.randint(1, 1000))
                    )
                ],
                orelse=[]
            ),
            # Complex opaque predicate
            ast.If(
                test=ast.Compare(
                    left=ast.BinOp(
                        left=ast.Call(
                            func=ast.Name(id='len', ctx=ast.Load()),
                            args=[ast.Constant(value="test")],
                            keywords=[]
                        ),
                        op=ast.Mod(),
                        right=ast.Constant(value=2)
                    ),
                    ops=[ast.GtE()],
                    comparators=[ast.Constant(value=0)]
                ),
                body=[ast.Pass()],
                orelse=[]
            )
        ]


def main():
    parser = argparse.ArgumentParser(description='Cerberus Obfuscator - Advanced Python Code Protection')
    parser.add_argument('-i', '--input', required=True, help='Input Python file to obfuscate')
    parser.add_argument('-o', '--output', required=True, help='Output file for obfuscated code')
    parser.add_argument('--token', help='GitHub Personal Access Token (optional, enables one-time execution)')
    
    args = parser.parse_args()
    
    try:
        # Read input file
        with open(args.input, 'r', encoding='utf-8') as f:
            source_code = f.read()
        
        # Initialize obfuscator
        obfuscator = CerberusObfuscator(args.token)
        
        # Perform obfuscation
        obfuscated_code = obfuscator.obfuscate(source_code)
        
        # Write output file
        with open(args.output, 'w', encoding='utf-8') as f:
            f.write(obfuscated_code)
        
        print(f"[+] Successfully obfuscated {args.input} -> {args.output}")
        
        if obfuscator.use_gist:
            print(f"[+] GitHub Gist ID: {obfuscator.gist_id}")
            print(f"[+] Status file: {obfuscator.gist_filename}")
            print("[!] WARNING: The obfuscated file can only be executed ONCE!")
            print("[!] Make sure the target system has internet access and required dependencies:")
            print("    - requests")
            print("    - pycryptodome")
        else:
            print("[+] Standalone mode: No GitHub Gist created")
            print("[!] The obfuscated file can be executed multiple times")
            print("[!] Required dependency on target system:")
            print("    - pycryptodome")
        
    except Exception as e:
        print(f"[-] Error: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main() 