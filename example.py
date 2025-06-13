#!/usr/bin/env python3
"""
Example Python script for demonstrating Cerberus Obfuscator
This script will be transformed into an unrecognizable form
"""

import os
import time
import json

def calculate_fibonacci(n):
    """Calculate fibonacci sequence up to n terms"""
    if n <= 0:
        return []
    elif n == 1:
        return [0]
    elif n == 2:
        return [0, 1]
    
    sequence = [0, 1]
    for i in range(2, n):
        next_fib = sequence[i-1] + sequence[i-2]
        sequence.append(next_fib)
    
    return sequence

def process_data(data_list):
    """Process a list of numbers with various operations"""
    results = {
        'sum': sum(data_list),
        'average': sum(data_list) / len(data_list) if data_list else 0,
        'max': max(data_list) if data_list else None,
        'min': min(data_list) if data_list else None
    }
    
    # Some conditional logic for demonstration
    if results['sum'] > 100:
        results['category'] = 'high'
    elif results['sum'] > 50:
        results['category'] = 'medium'
    else:
        results['category'] = 'low'
    
    return results

class DataProcessor:
    """A simple class for data processing"""
    
    def __init__(self, name):
        self.name = name
        self.processed_count = 0
        self.start_time = time.time()
    
    def process_item(self, item):
        """Process a single item"""
        self.processed_count += 1
        processed_item = {
            'original': item,
            'doubled': item * 2,
            'squared': item ** 2,
            'timestamp': time.time()
        }
        return processed_item
    
    def get_stats(self):
        """Get processing statistics"""
        elapsed_time = time.time() - self.start_time
        return {
            'processor_name': self.name,
            'items_processed': self.processed_count,
            'elapsed_time': elapsed_time,
            'items_per_second': self.processed_count / elapsed_time if elapsed_time > 0 else 0
        }

def main():
    """Main function demonstrating the functionality"""
    print("=== Cerberus Obfuscator Demo ===")
    
    # Test fibonacci function
    print("\n1. Fibonacci Sequence:")
    fib_sequence = calculate_fibonacci(10)
    print(f"First 10 fibonacci numbers: {fib_sequence}")
    
    # Test data processing
    print("\n2. Data Processing:")
    test_data = [15, 25, 35, 45, 55]
    results = process_data(test_data)
    print(f"Processing results: {json.dumps(results, indent=2)}")
    
    # Test class functionality
    print("\n3. Class-based Processing:")
    processor = DataProcessor("DemoProcessor")
    
    for i in range(1, 6):
        result = processor.process_item(i * 10)
        print(f"Processed item {i}: {result}")
    
    stats = processor.get_stats()
    print(f"\nProcessing stats: {json.dumps(stats, indent=2)}")
    
    # Some secret information (will be encrypted)
    secret_key = "MySecretKey12345"
    secret_data = "This is confidential information that should be protected"
    
    print(f"\n4. Secret Information:")
    print(f"Key: {secret_key}")
    print(f"Data: {secret_data}")
    
    # Conditional execution based on environment
    if os.getenv('DEBUG', 'false').lower() == 'true':
        print("\nDEBUG MODE: Additional information displayed")
        print(f"Current working directory: {os.getcwd()}")
        print(f"Python path: {os.path.dirname(os.__file__)}")
    
    print("\n=== Demo Complete ===")

if __name__ == "__main__":
    main() 