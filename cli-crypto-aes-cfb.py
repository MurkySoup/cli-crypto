#!/usr/bin/env python3
# -*- coding: utf-8 -*-


"""
Command Line String Crypto - 0.9.2-BETA (do not distribute)
By Rick Pelletier (galiagante@gmail.com), 06 April 2022
Last Update: 25 July 2023

Example given:

# ./cli-crypto-aes-cfb.py -e -s "$(date +%FT%T.%3N%z) - West side bell tower at midnight. Bring hot dogs and jello."

Example output:

I857BFgpJzkYlSTGRg0Tu3FxCRela/bxeiYrM19AJQIuqkkt7N4gV4X/8giBj5OSY68HVwZ177p6nMCIRUN+PrtLBBzH/5k/E764qahNXRsUu6VrN3hUCkXBP5902ZLxpkcUgbuwm1FODQ==

Features:
- Uses AES-256-CFB (ciper feedbas mode) to perform en/decryption on strings via command-line interface.
- Great for handling short messages over low-volume channels.
- An encryption key string can be supplied via command-line argument or by setting an environment variable named 'CLI_CRYPTO_KEY'.
- A hash cycling value can be supplied via command-line argument or by setting an environment variable named 'CLI_CRYPTO_ROUNDS'
"""


import os
import sys
import base64
import hashlib
import argparse
from Crypto import Random
from Crypto.Cipher import AES


def key_setup(key_string: str, rounds: int = 1) -> bytes:

    value = hashlib.sha256(key_string.encode('utf-8')).digest()

    for k in range(rounds):
        value = hashlib.sha256(value).digest()

    return value


def encrypt_string(key_string: str, message_string: str, rounds: int) -> str:

    private_key = key_setup(key_string, rounds)

    try:
        padded = message_string.encode('utf-8').ljust(16, b'\0')
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(private_key, AES.MODE_CFB, iv, segment_size=128)
        enc = cipher.encrypt(padded)[:len(message_string)]
        return base64.b64encode(iv + enc).decode()
    except Error as e:
        print(e)
        return False


def decrypt_string(key_string: str, message_string: str, rounds: int) -> str:

    private_key = key_setup(key_string, rounds)

    try:
        message_string = base64.b64decode(message_string.encode())
        iv, value = message_string[:16], message_string[16:]
        padded = value.ljust(16, b'\0')
        cipher = AES.new(private_key, AES.MODE_CFB, iv, segment_size=128)
        return cipher.decrypt(padded)[:len(value)].decode()
    except Error as e:
        print(e)
        return False


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-k', '--key', help='encryption key string', type=str, required=False) # can be supplied via env var
    parser.add_argument('-r', '--rounds', help='number of hash cycles to apply to encryption key string', type=int, required=False) # can be supplied via env var
    parser.add_argument('-s', '--string', help='string to en-/de-crypt', type=str, required=True)
    command_group = parser.add_mutually_exclusive_group(required=True)
    command_group.add_argument('-e', '--encrypt', help='enable encryption mode', action='store_true')
    command_group.add_argument('-d', '--decrypt', help='enable decryption mode', action='store_true')
    args = parser.parse_args()

    if args.key:
        key_string = args.key
    elif os.environ['CLI_CRYPTO_KEY']:
        key_string = os.environ['CLI_CRYPTO_KEY']
    else:
        key_string = None

    if args.rounds:
        rounds = args.rounds
    elif os.environ['CLI_CRYPTO_ROUNDS']:
        rounds = int(os.environ['CLI_CRYPTO_ROUNDS'])
    else:
        rounds = 1

    if args.encrypt:
        result = encrypt_string(key_string, args.string, rounds)
    else:
        result = decrypt_string(key_string, args.string, rounds)

    if result:
        print(result)
        sys.exit(0)
    else:
        print('Error')
        sys.exit(1)
else:
    sys.exit(1)

# end of script (cli-crypto-aes-cfb.py)
