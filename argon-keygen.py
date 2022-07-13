#!/usr/bin/env python3
# -*- coding: utf-8 -*-


"""
Argon-based password generator, version 0.3-beta (do not distribute)
By Rick Pelletier (galiagante@gmail.com), 23 June 2022
Last pdate: 13 July 2022

Ref: https://en.wikipedia.org/wiki/Argon2
Ref: https://github.com/p-h-c/phc-winner-argon2
Ref: https://datatracker.ietf.org/doc/html/rfc9106

Note: Due to the nature of this hashing algorithm, you will never get the same hash twice for
a given input string, but the resulting string makes for a very solid 'password'.
"""


import sys
import argparse
from argon2 import PasswordHasher, Type


if __name__ == '__main__':
  parser = argparse.ArgumentParser()
  parser.add_argument('-s', '--string', type=str, required=True, help='String to Hash')
  args = parser.parse_args()

  if args.string:
    ph = PasswordHasher(memory_cost=262144, time_cost=4, parallelism=2, hash_len=64, type=Type.ID)
    passwordHash = ph.hash(args.string)
    hash_array = passwordHash.split('$')
    print(f'{hash_array[4] + hash_array[5]}')
  else:
    print('ERROR: Argument is empty')
    sys.exit(1)

  sys.exit(0)
else:
  sys.exit(1)

# end of script

