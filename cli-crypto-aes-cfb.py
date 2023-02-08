#!/usr/bin/env python3
# -*- coding: utf-8 -*-


"""
Command Line String Crypto - 0.8.5-BETA (do not distribute)
By Rick Pelletier (galiagante@gmail.com), 06 April 2022
Last Update: 08 Feb 2023

Example given:

# ./cli-crypto-aes-cfb.py -e -s "$(date +%FT%T.%3N%z) - West side bell tower at midnight. Bring hot dogs and jello."

Output:

I857BFgpJzkYlSTGRg0Tu3FxCRela/bxeiYrM19AJQIuqkkt7N4gV4X/8giBj5OSY68HVwZ177p6nMCIRUN+PrtLBBzH/5k/E764qahNXRsUu6VrN3hUCkXBP5902ZLxpkcUgbuwm1FODQ==

Features:
- Uses AES-256-CFB to perform en/decryption on strings via command-line interface.
- Great for handling short messages over low-volume channels.
- An encryption key string can be supplied via command-line argument or by setting an environment variable named 'CLI_CRYPTO_KEY'.
- A hash cycling value can be supplied via command-line argument or by setting an environment variable named 'CLI_CRYPTO_ROUNDS'

TODO:
- Maybe a version of this using CTR mode is a better idea?
"""


import os
import sys
import base64
import hashlib
import argparse
from Crypto import Random
from Crypto.Cipher import AES


def key_setup(key_string, rounds=1):
  value = hashlib.sha256(key_string.encode('utf-8')).digest()

  for k in range(0, rounds):
    value = hashlib.sha256(value).digest()

  return value


def encrypt_string(key_string, message_string, rounds):
  private_key = key_setup(key_string, rounds)

  try:
    rem = len(message_string) % 16
    padded = str.encode(message_string) + (b'\0' * (16 - rem)) if rem > 0 else str.encode(message_string)
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(private_key, AES.MODE_CFB, iv, segment_size=128)
    enc = cipher.encrypt(padded)[:len(message_string)]
    return base64.b64encode(iv + enc).decode()
  except:
    return False


def decrypt_string(key_string, message_string, rounds):
  private_key = key_setup(key_string, rounds)

  try:
    message_string = base64.b64decode(message_string)
    iv, value = message_string[:16], message_string[16:]
    rem = len(value) % 16
    padded = value + (b'\0' * (16 - rem)) if rem > 0 else value
    cipher = AES.new(private_key, AES.MODE_CFB, iv, segment_size=128)
    return (cipher.decrypt(padded)[:len(value)]).decode()
  except:
    return False



if __name__ == '__main__':
  exit_value = 0
  rounds = 1

  parser = argparse.ArgumentParser()

  option_group = parser.add_argument('-k', '--key', help='key string', type=str)
  option_group = parser.add_argument('-r', '--rounds', help='number of hash cycles to apply to key string', type=int)
  option_group = parser.add_argument('-s', '--string', help='string to en-/de-crypt', type=str)
  command_group = parser.add_mutually_exclusive_group()
  command_group.add_argument('-e', '--encrypt', help='string to encrypt', action='store_true')
  command_group.add_argument('-d', '--decrypt', help='string to decrypt', action='store_true')

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

  if key_string:
    if args.encrypt:
      encrypted_string = encrypt_string(key_string, args.string, rounds)

      if encrypted_string:
        print(encrypted_string)
      else:
        print('Encryption error')
        exit_value = 1

    elif args.decrypt:
      decrypted_string = decrypt_string(key_string, args.string, rounds)

      if decrypted_string:
        print(decrypted_string)
      else:
        print('Decryption error')
        exit_value = 1

    else:
      print('Use --help to see command line options')
      exit_value = 1

  else:
    print('No valid key string presented')
    exit_value = 1

  sys.exit(exit_value)
else:
  sys.exit(1)

# end of script
