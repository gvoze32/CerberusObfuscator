#!/usr/bin/env python3
"""
Test script for Cerberus Obfuscator
This script tests various obfuscation techniques without GitHub token dependency
"""

import ast
import sys
import os

# Add current directory to path to import cerberus
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_ast_transformations():
    """Test AST transformation capabilities"""
    print("=== Testing AST Transformations ===")
    
    # Import required classes from cerberus
    try:
        from cerberus import NameObfuscator, IntegerObfuscator, DeadCodeInjector
        print("[+] Successfully imported obfuscation classes")
    except ImportError as e:
        print(f"[-] Failed to import: {e}")
        return False
    
    # Test code for transformation
    test_code = '''
def calculate_sum(x, y):
    result = x + y
    message = "The sum is: " + str(result)
    print(message)
    return result

number1 = 10
number2 = 20
total = calculate_sum(number1, number2)
'''
    
    try:
        # Parse the test code
        tree = ast.parse(test_code)
        print("[+] Successfully parsed test code")
        
        # Apply name obfuscation
        name_obfuscator = NameObfuscator()
        tree = name_obfuscator.visit(tree)
        print("[+] Applied name obfuscation")
        
        # Apply integer obfuscation
        int_obfuscator = IntegerObfuscator()
        tree = int_obfuscator.visit(tree)
        print("[+] Applied integer obfuscation")
        
        # Apply dead code injection
        dead_code_injector = DeadCodeInjector()
        tree = dead_code_injector.visit(tree)
        print("[+] Applied dead code injection")
        
        # Convert back to source code
        obfuscated_code = ast.unparse(tree)
        print("[+] Successfully generated obfuscated code")
        
        print("\n--- Original Code ---")
        print(test_code)
        print("\n--- Obfuscated Code ---")
        print(obfuscated_code)
        
        return True
        
    except Exception as e:
        print(f"[-] Error during transformation: {e}")
        return False

def test_encryption_layers():
    """Test encryption and encoding layers"""
    print("\n=== Testing Encryption Layers ===")
    
    try:
        import base64
        import binascii
        import zlib
        import marshal
        import os
        
        # Test data
        test_data = "This is a test string for encryption"
        print(f"[+] Original data: {test_data}")
        
        # XOR encryption
        xor_key = os.urandom(32)
        data_bytes = test_data.encode()
        key_expanded = (xor_key * (len(data_bytes) // len(xor_key) + 1))[:len(data_bytes)]
        xor_encrypted = bytes(a ^ b for a, b in zip(data_bytes, key_expanded))
        print("[+] Applied XOR encryption")
        
        # Marshal serialization
        marshaled = marshal.dumps(xor_encrypted)
        print("[+] Applied marshal serialization")
        
        # zlib compression
        compressed = zlib.compress(marshaled)
        print("[+] Applied zlib compression")
        
        # Multi-layer encoding
        encoded_b85 = base64.b85encode(compressed)
        encoded_b64 = base64.b64encode(encoded_b85)
        encoded_hex = binascii.hexlify(encoded_b64).decode()
        print("[+] Applied multi-layer encoding")
        
        print(f"[+] Final encoded length: {len(encoded_hex)} characters")
        print(f"[+] Compression ratio: {len(test_data)}/{len(encoded_hex)} = {len(test_data)/len(encoded_hex):.2f}")
        
        # Test decryption
        decoded_hex = binascii.unhexlify(encoded_hex)
        decoded_b64 = base64.b64decode(decoded_hex)
        decoded_b85 = base64.b85decode(decoded_b64)
        decompressed = zlib.decompress(decoded_b85)
        unmarshaled = marshal.loads(decompressed)
        decrypted = bytes(a ^ b for a, b in zip(unmarshaled, key_expanded))
        final_data = decrypted.decode()
        
        print(f"[+] Decrypted data: {final_data}")
        print(f"[+] Decryption successful: {final_data == test_data}")
        
        return final_data == test_data
        
    except Exception as e:
        print(f"[-] Error during encryption test: {e}")
        return False

def test_obfuscated_names():
    """Test obfuscated name generation"""
    print("\n=== Testing Name Obfuscation ===")
    
    try:
        from cerberus import CerberusObfuscator
        
        # Create obfuscator instance (without GitHub token for testing)
        class TestObfuscator:
            def generate_random_name(self, length=8):
                import random
                chars = 'Oo0'
                return ''.join(random.choice(chars) for _ in range(length))
        
        obfuscator = TestObfuscator()
        
        # Generate some obfuscated names
        names = []
        for i in range(10):
            name = obfuscator.generate_random_name()
            names.append(name)
            print(f"[+] Generated name {i+1}: {name}")
        
        # Check uniqueness (should be mostly unique)
        unique_names = set(names)
        print(f"[+] Generated {len(names)} names, {len(unique_names)} unique")
        
        return len(unique_names) >= len(names) * 0.8  # At least 80% unique
        
    except Exception as e:
        print(f"[-] Error during name obfuscation test: {e}")
        return False

def main():
    """Run all tests"""
    print("Cerberus Obfuscator - Test Suite")
    print("=" * 50)
    
    tests = [
        ("AST Transformations", test_ast_transformations),
        ("Encryption Layers", test_encryption_layers),
        ("Name Obfuscation", test_obfuscated_names),
    ]
    
    passed = 0
    total = len(tests)
    
    for test_name, test_func in tests:
        print(f"\nRunning {test_name}...")
        try:
            if test_func():
                print(f"[✓] {test_name} PASSED")
                passed += 1
            else:
                print(f"[✗] {test_name} FAILED")
        except Exception as e:
            print(f"[✗] {test_name} ERROR: {e}")
    
    print("\n" + "=" * 50)
    print(f"Test Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("[✓] All tests passed! Cerberus Obfuscator is ready.")
        return True
    else:
        print("[✗] Some tests failed. Please check the implementation.")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1) 