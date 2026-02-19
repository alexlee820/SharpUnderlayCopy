from Crypto.Cipher import AES

def aes256_cbc_decrypt(ciphertext_path, plaintext_path, key):
    # Key must be 32-bytes (256 bit)
    if isinstance(key, str):
        key = key.encode('utf-8')
    if len(key) > 32:
        key = key[:32]
    elif len(key) < 32:
        key = key.ljust(32, b'\0')
    iv = b'\x00' * 16  # 16 bytes of zero

    with open(ciphertext_path, 'rb') as fin:
        ciphertext = fin.read()

    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext)
    # Optionally unpad if you padded before encrypting (PKCS7)
    unpadded = unpad_pkcs7(plaintext)
    with open(plaintext_path, 'wb') as fout:
        fout.write(unpadded)

def unpad_pkcs7(data):
    if not data:
        return data
    pad_len = data[-1]
    if pad_len < 1 or pad_len > 16:
        return data
    return data[:-pad_len]

if __name__ == '__main__':
    import sys
    if len(sys.argv) < 4:
        print(f"Usage: {sys.argv[0]} <encrypted_file> <output_file> <key>")
        print("Key must match encryption key (32 bytes or shorter, utf-8, will pad with zeros).")
        sys.exit(1)
    aes256_cbc_decrypt(sys.argv[1], sys.argv[2], sys.argv[3])
    print(f"Decryption complete: {sys.argv[2]}")