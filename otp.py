import random
import pathlib
import argparse
import base64
from os import urandom

# Reading the input file
def file_reader(file_location):
    data = ''
    file = pathlib.Path(file_location)
    if file.is_file() and file.suffix == ".txt":
        with open(file, "r") as read_file:
            data = read_file.read() 
            data = str(data)
    else:
        print("Couldn't locate the file")
        exit()

    return data

# Writing the output
def file_writter(key, ciphertext, recoverdtext):
    if ciphertext:
        #Writing the Log
        data = f"KEY: {key}\nCIPHERTEXT: {str(ciphertext)[2:-1]}"
        with open("otp_log.txt", "w+") as output:
            output.write(data)
        #Writing the encrypted data only
        with open("ciphertext.txt", "w+") as cipher:
            cipher.write(str(ciphertext)[2:-1])
    
    elif recoverdtext:
        data = recoverdtext
        with open("decrypted.txt", "w+") as output:
            output.write(data)
        print(f"[+] Decrypted message stored in the 'decrypted.txt'\n")
    
    else:
        print("[-] Something wrong happended while writing...Check file permissions!!!")

#Random Key Generator
def key_generator(message):
    key = urandom(len(message))

    return key

# XOR Function
def xor_fuction(key, message):
    xored_message = ''
    #XORring each letter of the message with each letter of the key
    for i in range(len(key)):
        #Character to Decimal
        ascii_key = ord(key[i])
        ascii_letter = ord(message[i])        
        #XORing the values
        xor = ascii_key ^ ascii_letter
        #For troubleshooting only
        #print(f"{key[i]} [{ascii_key}] XOR {message[i]} [{ascii_letter}] = {chr(xor)} [{xor}]")        
        #Decimal to Char
        xored_message+=chr(xor)

    return xored_message

#Main OTP Function
def one_time_pad(user_key, mode, input_file):
    #This function is for either encrypting or decrypting the message
    #based on the user's choice
    return_key = None
    return_message = None
    try:
        #For encryption, we will generate a random key
        if mode == encrypt_option:
            message = file_reader(input_file)
            #Generating a random key
            key = key_generator(message)
            ciphertext = xor_fuction(key, message)
            #Encoding
            byte_ciphertext = ciphertext.encode("utf-8")
            ciphertext = base64.b64encode(byte_ciphertext)

            return_key, return_message = key, ciphertext
        
        #For Decryption, we will use user provided key
        elif mode == decrypt_option:
            key = user_key        
            message = file_reader(input_file)
            #Decoding the base64
            try:
                plain_message = base64.b64decode(message)
                plain_message = plain_message.decode("utf-8")
                if len(key) != len(plain_message):
                    print("[-] Key length and message length doesn't match")
                    exit()
                else:
                    plaintext = xor_fuction(user_key, plain_message)
                    return_key, return_message = key, plaintext
            except:
                print("\nSomething went wron while decrypting the data....")
                print("Make sure that provided file contain base64 encoded data..\n")
        else:
            print("[!] Please select correct mode")
    
    except Exception as error:
        return f"[-] One-Time-Pad function crashed with Error\n{error}"
    
    return return_key, return_message

#CLI Argument Parser
def initializing():
    #The following few lines are for options, these are the options that can be passed through CLI
    parser = argparse.ArgumentParser(description="One-Time Pad (OTP): Encrypt and Decrypt.")    
    
    #Passing the Key
    parser.add_argument("-k", "--key", help="Provide the key for decryption", type=str)
    #Passing the input file
    parser.add_argument("-i", "--input", help="Provide an Input file, ciphertext/plaintext", required=True, type=str)    
    
    #Option for either using encryption or decryption mode
    encrypt_decrypt_group = parser.add_mutually_exclusive_group(required=True)
    encrypt_decrypt_group.add_argument("-e", "--encrypt", help="Encryption Option", action="store_true")
    encrypt_decrypt_group.add_argument("-d", "--decrypt", help="Decryption Option", action="store_true")
    
    args = parser.parse_args()

    return args.key, args.input, args.encrypt, args.decrypt

# Main Executor
if __name__ == "__main__":
    print()
    print('#'*75)
    print("This is an OTP encryption/decryption program...")
    print("After Encryption, the ciphertext and the key is stored in the 'ciphertext_log.txt' file..")
    print("For analysis, either feed a file that has ciphertext or plaintext...")
    print('#'*75)
    user_key, file_input, encrypt_option, decrypt_option = initializing()
    ### Option for encryption/decryption
    if encrypt_option:
        print(f"\n[+] Encryption mode selected...")
        print(f"\n[+] Encrypting the plaintext file...")
        key, ciphertext = one_time_pad(user_key, encrypt_option, file_input)
        #Write the ciphertext
        file_writter(key, ciphertext, None)
        print(f"\n[+] ENCRYPTION KEY:{key}")
        print(f"\n[+] Message Encrypted.....Key and the Ciphertext is stored in otp_log.txt\n")
        print(f"[+] Encrypted message stored in 'ciphertext.txt'\n")
        # print(f"CIPHERTEXT:{ciphertext}")
            
    elif decrypt_option:
        if not user_key:
            print("\n[-] Please provide a key -k to decrypt or type -h for help")
            exit()
        else:
            print(f"\n[+] Decryption mode selected...")
            print(f"\n[+] Decrypting the ciphertext\n")
            key, plaintext = one_time_pad(user_key, decrypt_option, file_input)            
            print(f"[+] DECRYPTED TEXT: {plaintext}\n")
            file_writter(key, None, plaintext)
