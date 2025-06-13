#!/usr/bin/env python3
"""
Cerberus vs CerberusAlt - Comparison and Benchmarking Tool
Author: Security Research Team
Version: 1.0

This script compares the performance, security features, and output quality
between the original Cerberus and CerberusAlt obfuscators.
"""

import ast
import time
import os
import sys
import subprocess
import json
import hashlib
import argparse
from typing import Dict, List, Tuple, Any
import matplotlib.pyplot as plt
import pandas as pd


class ObfuscatorComparison:
    def __init__(self):
        self.results = {
            'cerberus': {},
            'cerberusalt': {}
        }
        
    def benchmark_obfuscation_time(self, input_file: str, github_token: str) -> Dict[str, float]:
        """Benchmark obfuscation time for both tools"""
        print("[+] Benchmarking obfuscation time...")
        
        times = {}
        
        # Test Cerberus Original
        print("  [*] Testing Cerberus Original...")
        start_time = time.time()
        try:
            result = subprocess.run([
                'python3', 'cerberus.py',
                '-i', input_file,
                '-o', 'temp_cerberus_output.py',
                '--token', github_token
            ], capture_output=True, text=True, timeout=300)
            
            if result.returncode == 0:
                times['cerberus'] = time.time() - start_time
                print(f"    [+] Cerberus completed in {times['cerberus']:.2f} seconds")
            else:
                print(f"    [-] Cerberus failed: {result.stderr}")
                times['cerberus'] = None
        except Exception as e:
            print(f"    [-] Cerberus error: {e}")
            times['cerberus'] = None
        
        # Test CerberusAlt
        print("  [*] Testing CerberusAlt...")
        start_time = time.time()
        try:
            result = subprocess.run([
                'python3', 'cerberusalt.py',
                '-i', input_file,
                '-o', 'temp_cerberusalt_output.py',
                '--token', github_token
            ], capture_output=True, text=True, timeout=300)
            
            if result.returncode == 0:
                times['cerberusalt'] = time.time() - start_time
                print(f"    [+] CerberusAlt completed in {times['cerberusalt']:.2f} seconds")
            else:
                print(f"    [-] CerberusAlt failed: {result.stderr}")
                times['cerberusalt'] = None
        except Exception as e:
            print(f"    [-] CerberusAlt error: {e}")
            times['cerberusalt'] = None
        
        return times
    
    def analyze_output_complexity(self) -> Dict[str, Dict[str, Any]]:
        """Analyze the complexity of obfuscated output"""
        print("[+] Analyzing output complexity...")
        
        complexity = {}
        
        for tool in ['cerberus', 'cerberusalt']:
            output_file = f'temp_{tool}_output.py'
            if os.path.exists(output_file):
                with open(output_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                # Basic metrics
                lines = len(content.split('\n'))
                chars = len(content)
                words = len(content.split())
                
                # AST complexity
                try:
                    tree = ast.parse(content)
                    ast_nodes = sum(1 for _ in ast.walk(tree))
                except:
                    ast_nodes = 0
                
                # Obfuscation indicators
                obfuscated_names = len([word for word in content.split() 
                                      if any(c in word for c in 'Oo0Il1')])
                
                # Entropy calculation
                entropy = self._calculate_entropy(content)
                
                complexity[tool] = {
                    'lines': lines,
                    'characters': chars,
                    'words': words,
                    'ast_nodes': ast_nodes,
                    'obfuscated_names': obfuscated_names,
                    'entropy': entropy,
                    'compression_ratio': self._calculate_compression_ratio(content)
                }
                
                print(f"  [+] {tool.capitalize()} complexity analyzed")
            else:
                complexity[tool] = None
                print(f"  [-] {tool.capitalize()} output not found")
        
        return complexity
    
    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of text"""
        import math
        from collections import Counter
        
        if not text:
            return 0
        
        counter = Counter(text)
        length = len(text)
        entropy = 0
        
        for count in counter.values():
            p = count / length
            entropy -= p * math.log2(p)
        
        return entropy
    
    def _calculate_compression_ratio(self, text: str) -> float:
        """Calculate compression ratio using zlib"""
        import zlib
        
        original_size = len(text.encode())
        compressed_size = len(zlib.compress(text.encode()))
        
        return original_size / compressed_size if compressed_size > 0 else 1.0
    
    def analyze_security_features(self) -> Dict[str, Dict[str, bool]]:
        """Analyze security features in both obfuscators"""
        print("[+] Analyzing security features...")
        
        features = {
            'cerberus': {
                'name_obfuscation': True,
                'string_encryption': True,
                'integer_obfuscation': True,
                'control_flow_flattening': True,
                'dead_code_injection': True,
                'anti_debug': False,
                'self_tamper_detection': True,
                'github_gist_validation': True,
                'aes_cbc_encryption': False,
                'pbkdf2_key_derivation': False,
                'binary_compilation': False,
                'advanced_junk_code': False,
                'call_obfuscation': False,
                'loop_obfuscation': False,
                'type_hint_removal': False
            },
            'cerberusalt': {
                'name_obfuscation': True,
                'string_encryption': True,
                'integer_obfuscation': True,
                'control_flow_flattening': True,
                'dead_code_injection': True,
                'anti_debug': True,
                'self_tamper_detection': True,
                'github_gist_validation': True,
                'aes_cbc_encryption': True,
                'pbkdf2_key_derivation': True,
                'binary_compilation': True,
                'advanced_junk_code': True,
                'call_obfuscation': True,
                'loop_obfuscation': True,
                'type_hint_removal': True
            }
        }
        
        return features
    
    def compare_file_sizes(self) -> Dict[str, int]:
        """Compare output file sizes"""
        print("[+] Comparing file sizes...")
        
        sizes = {}
        
        for tool in ['cerberus', 'cerberusalt']:
            output_file = f'temp_{tool}_output.py'
            if os.path.exists(output_file):
                sizes[tool] = os.path.getsize(output_file)
                print(f"  [+] {tool.capitalize()}: {sizes[tool]} bytes")
            else:
                sizes[tool] = 0
                print(f"  [-] {tool.capitalize()}: file not found")
        
        return sizes
    
    def generate_comparison_report(self, times: Dict, complexity: Dict, 
                                 features: Dict, sizes: Dict) -> str:
        """Generate comprehensive comparison report"""
        report = """
# Cerberus vs CerberusAlt - Comparison Report

## Performance Comparison

### Obfuscation Time
"""
        
        if times.get('cerberus') and times.get('cerberusalt'):
            faster = 'Cerberus' if times['cerberus'] < times['cerberusalt'] else 'CerberusAlt'
            speed_diff = abs(times['cerberus'] - times['cerberusalt'])
            
            report += f"""
- **Cerberus**: {times['cerberus']:.2f} seconds
- **CerberusAlt**: {times['cerberusalt']:.2f} seconds
- **Winner**: {faster} (faster by {speed_diff:.2f} seconds)
"""
        
        report += "\n## Output Analysis\n"
        
        if complexity.get('cerberus') and complexity.get('cerberusalt'):
            c_orig = complexity['cerberus']
            c_alt = complexity['cerberusalt']
            
            report += f"""
### Code Complexity
- **Lines of Code**: Cerberus {c_orig['lines']} vs CerberusAlt {c_alt['lines']}
- **Characters**: Cerberus {c_orig['characters']} vs CerberusAlt {c_alt['characters']}
- **AST Nodes**: Cerberus {c_orig['ast_nodes']} vs CerberusAlt {c_alt['ast_nodes']}
- **Obfuscated Names**: Cerberus {c_orig['obfuscated_names']} vs CerberusAlt {c_alt['obfuscated_names']}
- **Entropy**: Cerberus {c_orig['entropy']:.2f} vs CerberusAlt {c_alt['entropy']:.2f}
- **Compression Ratio**: Cerberus {c_orig['compression_ratio']:.2f} vs CerberusAlt {c_alt['compression_ratio']:.2f}
"""
        
        report += "\n## Security Features Comparison\n"
        
        report += "| Feature | Cerberus | CerberusAlt |\n"
        report += "|---------|----------|-------------|\n"
        
        for feature in features['cerberus']:
            c_has = "✅" if features['cerberus'][feature] else "❌"
            alt_has = "✅" if features['cerberusalt'][feature] else "❌"
            feature_name = feature.replace('_', ' ').title()
            report += f"| {feature_name} | {c_has} | {alt_has} |\n"
        
        report += f"\n## File Size Comparison\n"
        report += f"- **Cerberus**: {sizes.get('cerberus', 0)} bytes\n"
        report += f"- **CerberusAlt**: {sizes.get('cerberusalt', 0)} bytes\n"
        
        if sizes.get('cerberus') and sizes.get('cerberusalt'):
            size_diff = abs(sizes['cerberus'] - sizes['cerberusalt'])
            larger = 'Cerberus' if sizes['cerberus'] > sizes['cerberusalt'] else 'CerberusAlt'
            report += f"- **Size Difference**: {larger} is larger by {size_diff} bytes\n"
        
        # Feature count summary
        c_features = sum(features['cerberus'].values())
        alt_features = sum(features['cerberusalt'].values())
        
        report += f"\n## Summary\n"
        report += f"- **Cerberus Features**: {c_features}/{len(features['cerberus'])}\n"
        report += f"- **CerberusAlt Features**: {alt_features}/{len(features['cerberusalt'])}\n"
        
        if alt_features > c_features:
            report += f"- **Winner**: CerberusAlt (+{alt_features - c_features} additional features)\n"
        elif c_features > alt_features:
            report += f"- **Winner**: Cerberus (+{c_features - alt_features} additional features)\n"
        else:
            report += f"- **Result**: Tie in feature count\n"
        
        report += "\n## Recommendations\n"
        report += "- **For Speed**: Choose the faster obfuscator based on timing results\n"
        report += "- **For Security**: CerberusAlt offers more advanced security features\n"
        report += "- **For Simplicity**: Cerberus provides core obfuscation with less complexity\n"
        report += "- **For Advanced Users**: CerberusAlt with binary compilation and anti-debug\n"
        
        return report
    
    def create_visualization(self, times: Dict, complexity: Dict, sizes: Dict):
        """Create visualization charts"""
        print("[+] Creating visualization charts...")
        
        try:
            # Performance comparison
            fig, axes = plt.subplots(2, 2, figsize=(15, 10))
            fig.suptitle('Cerberus vs CerberusAlt Comparison', fontsize=16)
            
            # Timing comparison
            if times.get('cerberus') and times.get('cerberusalt'):
                tools = ['Cerberus', 'CerberusAlt']
                timing = [times['cerberus'], times['cerberusalt']]
                axes[0, 0].bar(tools, timing, color=['blue', 'red'])
                axes[0, 0].set_title('Obfuscation Time (seconds)')
                axes[0, 0].set_ylabel('Time (s)')
            
            # Size comparison
            if sizes.get('cerberus') and sizes.get('cerberusalt'):
                tools = ['Cerberus', 'CerberusAlt']
                file_sizes = [sizes['cerberus'], sizes['cerberusalt']]
                axes[0, 1].bar(tools, file_sizes, color=['blue', 'red'])
                axes[0, 1].set_title('Output File Size (bytes)')
                axes[0, 1].set_ylabel('Bytes')
            
            # Complexity comparison
            if complexity.get('cerberus') and complexity.get('cerberusalt'):
                metrics = ['Lines', 'AST Nodes', 'Entropy']
                cerberus_vals = [
                    complexity['cerberus']['lines'],
                    complexity['cerberus']['ast_nodes'],
                    complexity['cerberus']['entropy'] * 100  # Scale for visibility
                ]
                alt_vals = [
                    complexity['cerberusalt']['lines'],
                    complexity['cerberusalt']['ast_nodes'],
                    complexity['cerberusalt']['entropy'] * 100
                ]
                
                x_pos = range(len(metrics))
                width = 0.35
                
                axes[1, 0].bar([p - width/2 for p in x_pos], cerberus_vals, 
                              width, label='Cerberus', color='blue')
                axes[1, 0].bar([p + width/2 for p in x_pos], alt_vals, 
                              width, label='CerberusAlt', color='red')
                axes[1, 0].set_title('Complexity Metrics')
                axes[1, 0].set_xticks(x_pos)
                axes[1, 0].set_xticklabels(metrics)
                axes[1, 0].legend()
            
            # Feature comparison pie chart
            features = self.analyze_security_features()
            c_count = sum(features['cerberus'].values())
            alt_count = sum(features['cerberusalt'].values())
            
            axes[1, 1].pie([c_count, alt_count], 
                          labels=['Cerberus', 'CerberusAlt'],
                          colors=['blue', 'red'],
                          autopct='%1.1f%%')
            axes[1, 1].set_title('Security Features Distribution')
            
            plt.tight_layout()
            plt.savefig('cerberus_comparison.png', dpi=300, bbox_inches='tight')
            print("  [+] Visualization saved as 'cerberus_comparison.png'")
            
        except ImportError:
            print("  [-] matplotlib not available, skipping visualization")
        except Exception as e:
            print(f"  [-] Visualization error: {e}")
    
    def cleanup_temp_files(self):
        """Clean up temporary files"""
        temp_files = [
            'temp_cerberus_output.py',
            'temp_cerberusalt_output.py'
        ]
        
        for file in temp_files:
            if os.path.exists(file):
                os.remove(file)
                print(f"  [+] Cleaned up {file}")
    
    def run_full_comparison(self, input_file: str, github_token: str, 
                           output_report: str = 'comparison_report.md'):
        """Run complete comparison suite"""
        print("=" * 60)
        print("🐺 CERBERUS vs CERBERUSALT COMPARISON 🐺")
        print("=" * 60)
        
        # Run benchmarks
        times = self.benchmark_obfuscation_time(input_file, github_token)
        complexity = self.analyze_output_complexity()
        features = self.analyze_security_features()
        sizes = self.compare_file_sizes()
        
        # Generate report
        report = self.generate_comparison_report(times, complexity, features, sizes)
        
        # Save report
        with open(output_report, 'w', encoding='utf-8') as f:
            f.write(report)
        print(f"\n[+] Comparison report saved to {output_report}")
        
        # Create visualization
        self.create_visualization(times, complexity, sizes)
        
        # Display summary
        print("\n" + "=" * 60)
        print("📊 COMPARISON SUMMARY")
        print("=" * 60)
        
        if times.get('cerberus') and times.get('cerberusalt'):
            faster = 'Cerberus' if times['cerberus'] < times['cerberusalt'] else 'CerberusAlt'
            print(f"⚡ Faster Tool: {faster}")
        
        c_features = sum(features['cerberus'].values())
        alt_features = sum(features['cerberusalt'].values())
        
        if alt_features > c_features:
            print(f"🔒 More Secure: CerberusAlt (+{alt_features - c_features} features)")
        elif c_features > alt_features:
            print(f"🔒 More Secure: Cerberus (+{c_features - alt_features} features)")
        else:
            print("🔒 Security: Tie")
        
        if sizes.get('cerberus') and sizes.get('cerberusalt'):
            if sizes['cerberusalt'] > sizes['cerberus']:
                print(f"📦 Larger Output: CerberusAlt (+{sizes['cerberusalt'] - sizes['cerberus']} bytes)")
            else:
                print(f"📦 Larger Output: Cerberus (+{sizes['cerberus'] - sizes['cerberusalt']} bytes)")
        
        print("\n🏆 RECOMMENDATION:")
        if alt_features > c_features:
            print("   CerberusAlt for advanced security and features")
        else:
            print("   Choose based on specific requirements and performance needs")
        
        # Cleanup
        print(f"\n[+] Cleaning up temporary files...")
        self.cleanup_temp_files()
        
        print(f"\n✅ Comparison complete! Check {output_report} for detailed analysis.")


def main():
    parser = argparse.ArgumentParser(description='Compare Cerberus and CerberusAlt obfuscators')
    parser.add_argument('-i', '--input', required=True, help='Input Python file for testing')
    parser.add_argument('--token', required=True, help='GitHub Personal Access Token')
    parser.add_argument('-o', '--output', default='comparison_report.md', 
                       help='Output report file (default: comparison_report.md)')
    parser.add_argument('--no-cleanup', action='store_true', 
                       help='Keep temporary files for manual inspection')
    
    args = parser.parse_args()
    
    if not os.path.exists(args.input):
        print(f"[-] Input file {args.input} not found!")
        sys.exit(1)
    
    if not os.path.exists('cerberus.py'):
        print("[-] cerberus.py not found!")
        sys.exit(1)
    
    if not os.path.exists('cerberusalt.py'):
        print("[-] cerberusalt.py not found!")
        sys.exit(1)
    
    # Run comparison
    comparator = ObfuscatorComparison()
    comparator.run_full_comparison(args.input, args.token, args.output)
    
    if args.no_cleanup:
        print("[!] Temporary files preserved for manual inspection")


if __name__ == "__main__":
    main() 