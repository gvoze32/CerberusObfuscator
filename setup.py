#!/usr/bin/env python3
"""
Setup script for Cerberus Obfuscator
"""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="cerberus-obfuscator",
    version="1.0.0",
    author="Cyber Security Specialist",
    author_email="security@cerberus.dev",
    description="Advanced Multi-Layer Python Code Obfuscator",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/cerberus-security/cerberus-obfuscator",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "Topic :: Security :: Cryptography",
        "Topic :: Software Development :: Code Generators",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "cerberus=cerberus:main",
        ],
    },
    keywords="obfuscator, security, malware, python, encryption, protection",
    project_urls={
        "Bug Reports": "https://github.com/cerberus-security/cerberus-obfuscator/issues",
        "Source": "https://github.com/cerberus-security/cerberus-obfuscator",
        "Documentation": "https://github.com/cerberus-security/cerberus-obfuscator/wiki",
    },
) 