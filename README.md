# One-Time Pad (OTP) File Encryption Tool
## Overview
This project is an implementation of One-Time Pad (OTP) encryption for files using Python. It demonstrates how OTP achieves perfect secrecy in theory, while also highlighting why it is impractical in real-world systems.
The tool encrypts and decrypts files using XOR with a truly random, single-use key generated via the operating system’s cryptographically secure random source.
## Usage
### Encrypt a file
```python
python3 otp.py -f secret.txt -k secret.key -e
```
### Decrypt a file
```python
python3 otp.py -f secret.txt.encrypted -k secret.key -d
```
