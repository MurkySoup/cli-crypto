#!/usr/bin/env python3
# -*- coding: utf-8 -*-


"""
Command Line String Crypto - 0.10.1-BETA (do not distribute)
By Rick Pelletier (galiagante@gmail.com), 06 April 2022
Last Update: 09 August 2023

Example encryption given:

# ./cli-crypto-aes-cfb.py -e -s "$(date +%FT%T.%3N%z) - West side bell tower at midnight. Bring hot dogs and jello."

Example output:

I857BFgpJzkYlSTGRg0Tu3FxCRela/bxeiYrM19AJQIuqkkt7N4gV4X/8giBj5OSY68HVwZ177p6nMCIRUN+PrtLBBzH/5k/E764qahNXRsUu6VrN3hUCkXBP5902ZLxpkcUgbuwm1FODQ==

Features:
- Uses AES-256-CFB (ciper feedback mode) to perform en/decryption on strings via command-line interface.
- An encryption key string can be supplied via command-line argument or by setting an environment variable named 'CLI_CRYPTO_KEY'.
- Initialization Vector is randomy generated.
- A password hash cycling value can be supplied via command-line argument or by setting an environment variable named 'CLI_CRYPTO_ROUNDS'
- Great for handling short messages over low-volume channels.
"""


import os
import sys
import base64
import hashlib
import argparse
from Crypto import Random
from Crypto.Cipher import AES


def show_verbose(key_string:str, private_key:bytes, rounds:int, iv:bytes) -> None:
    print()
    print(f'Key String : {key_string}')
    print(f'Rounds     : {rounds}')
    print(f'Derived Key: {private_key.hex()}')
    print(f'Init Vector: {iv.hex()}')
    print()


def key_setup(key_string:str, rounds:int) -> bytes:
    try:
        value = hashlib.sha256(key_string.encode('utf-8')).digest()

        for k in range(rounds):
            value = hashlib.sha256(value).digest()

        return value
    except Exception as e:
        print(e)
        return False

      
def encrypt_string(private_key:bytes, message_string:str) -> str:
    try:
        padded = message_string.encode('utf-8').ljust(16, b'\0')
        cipher = AES.new(private_key, AES.MODE_CFB, iv, segment_size=128)
        enc = cipher.encrypt(padded)[:len(message_string)]

        if args.verbose:
            show_verbose(key_string, private_key, rounds, iv)

        return base64.b64encode(iv + enc).decode()
    except Exception as e:
        print(e)
        return False


def decrypt_string(private_key:bytes, message_string:str) -> str:
    try:
        message_string = base64.b64decode(message_string.encode())
        iv, value = message_string[:16], message_string[16:]
        padded = value.ljust(16, b'\0')
        cipher = AES.new(private_key, AES.MODE_CFB, iv, segment_size=128)

        if args.verbose:
            show_verbose(key_string, private_key, rounds, iv)

        return cipher.decrypt(padded)[:len(value)].decode()
    except Exception as e:
        print(e)
        return False


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-k', '--key', help='encryption key string', type=str, required=False)
    parser.add_argument('-r', '--rounds', help='number of hash cycles to apply to encryption key string', type=int, required=False)
    parser.add_argument('-s', '--string', help='string to en-/de-crypt', type=str, required=True)
    parser.add_argument('-v', '--verbose', help='verbose display', action='store_true', required=False)
    command_group = parser.add_mutually_exclusive_group(required=True)
    command_group.add_argument('-e', '--encrypt', help='enable encryption mode', action='store_true')
    command_group.add_argument('-d', '--decrypt', help='enable decryption mode', action='store_true')
    args = parser.parse_args()

    if args.key:
        key_string = args.key
    elif os.environ['CLI_CRYPTO_KEY']:
        key_string = str(os.environ['CLI_CRYPTO_KEY'])
    else:
        print('No key string available. Aborting.')
        sys.exit(1)

    if args.rounds:
        rounds = args.rounds
    elif os.environ['CLI_CRYPTO_ROUNDS']:
        rounds = int(os.environ['CLI_CRYPTO_ROUNDS'])
    else:
        rounds = 1

    if (private_key := key_setup(key_string, rounds)) == False:
        sys.exit(1)

    if args.encrypt:
        result = encrypt_string(private_key, args.string)

    if args.decrypt:
        result = decrypt_string(private_key, args.string)

    if result is not False:
        print(result)
        sys.exit(0)
    else:
        print('Unable to execute operation.')
        sys.exit(1)
else:
    sys.exit(1)

# end of script (cli-crypto-aes-cfb.py)
