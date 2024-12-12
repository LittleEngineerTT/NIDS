#!/usr/bin/env python3
import argparse

from cryptography.fernet import Fernet

def decrypt(file, key, output):
    # Loading key
    with open(key, 'rb') as filekey:
        key = filekey.read()
    fernet = Fernet(key)

    with open(file, 'rb') as enc_file:
        encrypted = enc_file.read()

    # Decrypt content
    decrypted = fernet.decrypt(encrypted)

    with open(output, 'wb') as dec_file:
        dec_file.write(decrypted)


def main():
    parser = argparse.ArgumentParser(description='Decrypt a Fernet encrypted file')
    parser.add_argument('-k', '--key', required=True, help='Fernet key')
    parser.add_argument('-f', '--file', required=True, help='Encrypted file')
    parser.add_argument('-o', '--output', required=True, help='Output file')

    args = parser.parse_args()

    decrypt(args.file, args.key, args.output)


if __name__ == '__main__':
    main()