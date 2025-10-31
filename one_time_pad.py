import os, sys, base64

CHUNK = 64 * 1024

#Random key Generator
def key_generator(length, key_path):
    with open(key_path, "wb") as key:
        #encoded_key = encoder(os.urandom(length))
        key.write(os.urandom(length))

#Encoder and Decoder
def encoder(message):
    encoded_message = base64.b64encode(message)
    return encoded_message
def decoder(message):
    decoded_message = base64.b64decode(message)
    return decoded_message

#XOR Function for Encryption/Decryption
def xor_function(key, input_file, output_file, decrypt):
    xor_bytes = []
    while True:
        #Breaking file into smaller chunks
        ptext_stream = input_file.read(CHUNK)
        key_stream = key.read(len(ptext_stream))
        if not ptext_stream:
            break
        # #Decode the Key and the Ciphertext for decryption
        # if decrypt == True:
        #     key_stream = decoder(key_stream)
        #     ptext_stream = decoder(ptext_stream)

        #Checking length miss-match
        if len(key_stream) != len(ptext_stream):
            print("[-] The key is too short")
            break
        # XOR each byte and collect the results
        for i in range(len(ptext_stream)):
            xor_value = ptext_stream[i] ^ key_stream[i]
            xor_bytes.append(xor_value)
        #List of Integers to Bytes
        output = bytes(xor_bytes)
        # if decrypt == False:
        #     output = encoder(output)
        # Write the encrypted chunk to output
        output_file.write(output)

# File Encryption Function
def encryption(key_path, plaintext_path, ciphertext_path):
    message_length = os.path.getsize(plaintext_path)
    key_generator(message_length, key_path)
    with open(key_path, "rb") as key, \
         open(plaintext_path, "rb") as plaintext, \
         open(ciphertext_path, "wb") as ciphertext:
        xor_function(key, plaintext, ciphertext, None)

# File Decryption Function
def decryption(key_path, ciphertext_path, decryptedtext_path):
    with open(key_path, "rb") as key, \
         open(ciphertext_path, "rb") as ciphertext, \
         open(decryptedtext_path, "wb") as decrypted_text:
        xor_function(key, ciphertext, decrypted_text, decrypt=True)

def main(argv):
    if len(argv) != 5:
        print("Usage: one_time_pad.py (encrypt|decrypt) input_file output_file key_path")
        return 2
    cmd, input_file, output_file, keypath = argv[1], argv[2], argv[3], argv[4]
    if cmd == "encrypt":
        encryption(keypath, input_file, output_file)
        print(f"Encrypted {input_file} -> {output_file}, key saved to {keypath}")
    elif cmd == "decrypt":
        decryption(keypath, input_file, output_file)
        print(f"Decrypted {input_file} -> {output_file}")
    else:
        print("Unknown command. Use encrypt or decrypt")
        return 2
    return 0
if __name__ == "__main__":
    sys.exit(main(sys.argv))
