#!/usr/bin/env python3
"""
Cerberus Obfuscator - Advanced Multi-Layer Python Code Obfuscator
Author: Cyber Security Specialist
Version: 1.0

Dependencies:
- requests
- pycryptodome

Usage:
python cerberus.py -i <input_file.py> -o <output_file.py> --token <github_access_token>
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
import zlib
from typing import Dict, List, Set, Any
import requests
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from Cryptodome.Util.Padding import pad, unpad


class CerberusObfuscator:
    def __init__(self, github_token: str):
        self.github_token = github_token
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
        chars = 'Oo0'
        return ''.join(random.choice(chars) for _ in range(length))
    
    def clean_source_code(self, source: str) -> str:
        """Layer 0: Remove comments and docstrings"""
        try:
            tree = ast.parse(source)
            cleaner = SourceCleaner()
            cleaned_tree = cleaner.visit(tree)
            return ast.unparse(cleaned_tree)
        except:
            # Fallback: simple regex cleaning
            lines = source.split('\n')
            cleaned_lines = []
            in_multiline_string = False
            
            for line in lines:
                stripped = line.strip()
                if not stripped or stripped.startswith('#'):
                    continue
                if '"""' in line or "'''" in line:
                    in_multiline_string = not in_multiline_string
                    continue
                if not in_multiline_string:
                    cleaned_lines.append(line)
                    
            return '\n'.join(cleaned_lines)
    
    def calculate_hash(self, code: str) -> str:
        """Calculate SHA-256 hash for anti-tampering"""
        return hashlib.sha256(code.encode()).hexdigest()
    
    def create_github_gist(self) -> tuple:
        """Create GitHub Gist for one-time execution tracking"""
        self.gist_filename = f"{''.join(random.choices(string.ascii_letters + string.digits, k=12))}.txt"
        
        gist_data = {
            "description": "Status tracking",
            "public": True,
            "files": {
                self.gist_filename: {
                    "content": "UNUSED"
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
        print("[+] Starting Cerberus Obfuscation Process...")
        
        # Layer 0: Preparation
        print("  [*] Layer 0: Cleaning source code...")
        cleaned_code = self.clean_source_code(source_code)
        self.original_hash = self.calculate_hash(cleaned_code)
        
        # Layer 1: AST Transformations
        print("  [*] Layer 1: Applying AST transformations...")
        obfuscated_ast = self.apply_ast_transformations(cleaned_code)
        
        # Layer 2: Encryption & Serialization
        print("  [*] Layer 2: Encrypting and serializing...")
        encrypted_data = self.encrypt_and_serialize(obfuscated_ast)
        
        # Layer 3: Compression & Encoding
        print("  [*] Layer 3: Compressing and encoding...")
        encoded_payload = self.compress_and_encode(encrypted_data)
        
        # Layer 4: Create GitHub Gist and Loader
        print("  [*] Layer 4: Creating GitHub Gist and loader stub...")
        gist_id, gist_filename = self.create_github_gist()
        loader_stub = self.create_loader_stub(encoded_payload, gist_id, gist_filename)
        
        print("[+] Obfuscation complete!")
        return loader_stub
    
    def apply_ast_transformations(self, source_code: str) -> str:
        """Layer 1: Apply all AST transformations"""
        tree = ast.parse(source_code)
        
        # Apply transformations in sequence
        transformers = [
            NameObfuscator(),
            StringObfuscator(self.aes_key),
            IntegerObfuscator(),
            ControlFlowFlattener(),
            DeadCodeInjector()
        ]
        
        for transformer in transformers:
            tree = transformer.visit(tree)
        
        return ast.unparse(tree)
    
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
        """Layer 3: zlib compression and multi-layer encoding"""
        # Compress
        compressed = zlib.compress(data)
        
        # Multi-layer encoding: Base85 -> Base64 -> Hex
        encoded_b85 = base64.b85encode(compressed)
        encoded_b64 = base64.b64encode(encoded_b85)
        encoded_hex = binascii.hexlify(encoded_b64).decode()
        
        return encoded_hex
    
    def create_loader_stub(self, payload: str, gist_id: str, gist_filename: str) -> str:
        """Layer 4: Create the final loader stub with one-time execution"""
        # Generate obfuscated variable names
        var_payload = self.generate_random_name()
        var_xor_key = self.generate_random_name()
        var_aes_key = self.generate_random_name()
        var_hash = self.generate_random_name()
        var_gist_id = self.generate_random_name()
        var_gist_file = self.generate_random_name()
        func_check = self.generate_random_name()
        func_decode = self.generate_random_name()
        func_decrypt_str = self.generate_random_name()
        
        # Create AES decryption function for strings
        aes_decrypt_func = f'''def {func_decrypt_str}(encrypted_b64):
 from Cryptodome.Cipher import AES
 from Cryptodome.Util.Padding import unpad
 import base64
 key = bytes({list(self.aes_key)})
 encrypted = base64.b64decode(encrypted_b64)
 cipher = AES.new(key, AES.MODE_ECB)
 decrypted = unpad(cipher.decrypt(encrypted), AES.block_size)
 return decrypted.decode()'''
        
        loader_template = f'''# Cerberus Protected Code - One-Time Execution Only
import sys,base64,binascii,zlib,marshal,hashlib,requests,os
{var_payload}="{payload}"
{var_xor_key}={list(self.xor_key)}
{var_hash}="{self.original_hash}"
{var_gist_id}="{gist_id}"
{var_gist_file}="{gist_filename}"

{aes_decrypt_func}

def {func_check}():
 try:
  url = f"https://api.github.com/gists/{{{var_gist_id}}}"
  response = requests.get(url, timeout=10)
  if response.status_code != 200:
   sys.exit(0)
  gist_data = response.json()
  if gist_data["files"][{var_gist_file}]["content"] != "UNUSED":
   sys.exit(0)
  patch_data = {{"files": {{{var_gist_file}: {{"content": "USED"}}}}}}
  requests.patch(url, json=patch_data, timeout=10)
 except:
  sys.exit(0)

def {func_decode}():
 decoded_hex = binascii.unhexlify({var_payload})
 decoded_b64 = base64.b64decode(decoded_hex)
 decoded_b85 = base64.b85decode(decoded_b64)
 decompressed = zlib.decompress(decoded_b85)
 unmarshaled = marshal.loads(decompressed)
 xor_key = bytes({var_xor_key})
 key_expanded = (xor_key * (len(unmarshaled) // len(xor_key) + 1))[:len(unmarshaled)]
 decrypted = bytes(a ^ b for a, b in zip(unmarshaled, key_expanded))
 if hashlib.sha256(decrypted).hexdigest() != {var_hash}:
  sys.exit(0)
 return decrypted.decode()

# Execute protection and payload
{func_check}()
exec({func_decode}())'''
        
        return loader_template


class SourceCleaner(ast.NodeVisitor):
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
            chars = 'Oo0'
            self.name_mapping[original_name] = ''.join(random.choice(chars) for _ in range(8))
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
        if isinstance(node.value, str) and len(node.value) > 1:
            encrypted = self.encrypt_string(node.value)
            # Replace with decryption call - will be handled in loader
            return ast.Call(
                func=ast.Name(id='O0o0O0o', ctx=ast.Load()),
                args=[ast.Constant(value=encrypted)],
                keywords=[]
            )
        return node


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
    parser.add_argument('--token', required=True, help='GitHub Personal Access Token')
    
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
        print(f"[+] GitHub Gist ID: {obfuscator.gist_id}")
        print(f"[+] Status file: {obfuscator.gist_filename}")
        print("[!] WARNING: The obfuscated file can only be executed ONCE!")
        print("[!] Make sure the target system has internet access and required dependencies:")
        print("    - requests")
        print("    - pycryptodome")
        
    except Exception as e:
        print(f"[-] Error: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main() 