from setuptools import setup, find_packages

setup(
    name="BlockCipherX",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "cryptography>=42.0.0"
    ],
    author="Your Name",
    description="Lightweight cryptography toolkit with AES, RSA and hashing support",
    python_requires=">=3.8",
)
