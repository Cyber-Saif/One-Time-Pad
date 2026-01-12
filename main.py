import os
import pathlib
import argparse
import hashlib

CHUNK = 64 * 1024

# Generating Key
def key_generator(Key_length: int, key_file: str):
    """Generates an equivalent key for encryption"""
    if key_file[-4:] != ".key":
        key_file = key_file+".key"
    
    if path_validator(key_file) == True:
        raise FileExistsError(f"""\n[!] A file with the following name '{key_file}' already exist...
                              \n[!] Please use a different name...\n""")
        
    try:
        with open(key_file, "wb+") as write_key:
            generated_key = os.urandom(Key_length)
            write_key.write((generated_key))
        print("\n[+] Encryption Key generated successfully!")
        os.chmod(key_file, 0o400)
    
        return True, key_file
    
    except Exception as e:
        print(f"""[-] Couldn't generate the key...\n
              The following error occured\n{e}""")
    
        return False, None

def calculate_hash(file):
    """Take files as an input and return the hash"""
    calculated_hash = None
    try:
        with open(file, "rb") as f:
            calculated_hash = hashlib.file_digest(f, 'sha256').hexdigest()
    
    # For Older versions
    except AttributeError:
        sha256_hash = hashlib.sha256()
        with open(file, "rb") as f:
            while chunk := f.read(4096):
                sha256_hash.update(chunk)
        calculated_hash = sha256_hash.hexdigest()
    
    except Exception as e:
        print(f"[-] An error occured while hashing the file\n{e}")
    
    return calculated_hash

#### Encryption & Decryption Section
# Encryption Function
def encryption(plaintext_file: str, encryption_key):
    """Encryptes the File using XOR"""

    print("[+] Encrypting the file...")
    
    try:    
        #Reading the file and XORing it
        with open(plaintext_file, "rb") as plaindata, \
            open(encryption_key, "rb") as key:
            encrypted_data = xor_function(plaindata, key)
        
        #Writing data to the file
        temp_file = f"{plaintext_file}.tmp"
        with open(temp_file, "wb") as writer:
            writer.write((encrypted_data))
        os.replace(temp_file, plaintext_file)
        print("[+] File Encrypted...\n")
        
        #Hash calculator
        calculated_hash = calculate_hash(plaintext_file)
        print(f"[+] Hash for the Encryptedfile {plaintext_file}\n[+] SHA256: {calculated_hash}")

        # Finalizer
        finalize(plaintext_file, encrypt=True)

    except Exception as e:
        print(f"""[-] Couldn't encrypt the file...\n
              Following error occured {e}""")

# Decryption Function
def decryption(ciphertext_file: str, decryption_key):
    """Decrypts the Ciphertext using the same XOR method"""
    if os.path.getsize(decryption_key) != os.path.getsize(ciphertext_file):
        raise ValueError("Key length mismatch — invalid OTP key")
    
    # Calculating the Hash before decryption
    calculated_hash = calculate_hash(ciphertext_file)
    print(f"[+] Hash before decrypting the {ciphertext_file}\n[+] SHA256: {calculated_hash}")
    
    print("\n[+] Decrypting the file...")
    
    try:
        #Reading the file and xoring it for decryption
        with open(ciphertext_file, "rb") as encrypted_data, \
            open(decryption_key, "rb") as key:
            decrypted_data = xor_function(encrypted_data, key)
        
        #Writing decrypted data to the  file
        print("[+] Writing data to the file...")

        temp_file = f"{ciphertext_file}.tmp"

        with open(temp_file, "wb+") as plaindata:
            plaindata.write(decrypted_data)        
        os.replace(temp_file, ciphertext_file)
        
        print("[+] File decrypted!\n")

        #Calculating the hash after decryption
        calculated_hash = calculate_hash(ciphertext_file)
        print(f"[+] Has for the Decryptedfile {ciphertext_file}\n[+] SHA256: {calculated_hash}")

        # Finalizer
        finalize(ciphertext_file, decrypt=True)
    
    except Exception as e :
        print(f"[-] The fllowing error occured while decryptiong the file...\n {e}")

### XOR Function
def xor_function(data, key) -> bytes:
    """Primary XOR function for both encryption and decryption"""
    xored_bytes = bytearray()
    while True:
        data_stream = data.read(CHUNK)
        key_stream = key.read(len(data_stream))
        
        if not data_stream:
            break
        if len(data_stream) != len(key_stream):
            print("[!] The key length does not match the data length")
            break
        
        for i in range(len(data_stream)):
            xored_bytes.append(data_stream[i] ^ key_stream[i])
        
    xored_data = bytes(xored_bytes)
    return xored_data

### Initializer Function
def initialize(file, encrypt=False, decrypt=False):
    file_ext = pathlib.Path(file)    
    if file_ext.suffix == ".encrypted":
        if encrypt == True:
            print(f"[!] Given file is already encrypted...\n[-] Quitting the program...")
            exit()
        elif decrypt == True:
            pass
    if (file_ext.suffix != ".encrypted") and decrypt == True:
        print(f"[!] The file '{file}' appear to be already encrypted...")
        exit()

### Finalizer Function
def finalize(file, encrypt=False, decrypt=False):
    current_file = file
    if encrypt == True:        
        encrypted_file = f"{current_file}.encrypted"
        os.rename(current_file, encrypted_file)
    elif decrypt == True:
        file_ext = pathlib.Path(current_file)
        if file_ext.suffix == ".encrypted":
            decrypted_file = current_file[:-10]
            os.rename(current_file, decrypted_file)
            
#### CLI Argument Parser
# Argument Parser
def argument_parser():
    """Initializer for all CLI options"""
    parser = argparse.ArgumentParser(description="One Time Pad (OTP): Encrypt and Decrypt.")
    
    #Passing the input file
    parser.add_argument("-f", "--file", help="Specify the file", required=True, type=str)
    
    #Key File
    parser.add_argument("-k", "--key", help="Provide the key for decryption", required=True, type=str)

    #Either using encryption or decryption mode
    encrypt_decrypt_group = parser.add_mutually_exclusive_group(required=True)
    encrypt_decrypt_group.add_argument("-e", "--encrypt", help="Encryption Option", action="store_true")
    encrypt_decrypt_group.add_argument("-d", "--decrypt", help="Decryption Option", action="store_true")
        
    args = parser.parse_args()
    
    return args.file, args.key, args.encrypt, args.decrypt

# File Path Validor
def path_validator(file_path: str) -> bool:
    file = pathlib.Path(file_path)
    if file.exists():
        return True
    else:
        return False

def main():
    file_location, key_file_location, encrypt_mode, decrypt_mode = argument_parser()
    if (path_validator(file_location) != True):
        raise ValueError (f"[!] Couldn't locate {file_location}\n[-] Exitting the program...")

    # For encryption
    if encrypt_mode:
        # Initializer
        initialize(file_location, encrypt=True)
        
        # Size of the file
        user_file_size = os.path.getsize(file_location)  
        
        # Calculating the Hash before encryption
        calculated_hash = calculate_hash(file_location)
        print(f"[+] Hash before encrypting the {file_location}\n[+] SHA256: {calculated_hash}")
        
        #Generate an equivalent key
        key_gen_status, key_file = key_generator(Key_length=user_file_size, key_file=key_file_location)
        if key_gen_status == True:            
            encryption(file_location, key_file)

    #For decryption
    elif decrypt_mode:
        if path_validator(key_file_location) != True:
            raise ValueError (f"[!] Couldn't locate {key_file_location}\n[-] Exitting the program...")

        initialize(file_location, decrypt=True)

        # Decryptig the data
        decryption(file_location, key_file_location)                
        

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("[-] keyboardInterrupt......")
    except FileNotFoundError:
        print("[!] The program couldn't find the specified file, please check the path")
