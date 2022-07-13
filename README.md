# cli-crypto

Command-Line String Cryptography: Intended for secure encryption and movement of data elements small enough to fit into command-line interfaces.

## Prerequisites

These utilities require Python 3.6+ (preferably 3.7+) and the following modules:

* sys
* os
* argparse
* argon2 (argon2-cffi)
* base64
* hashlib
* Crypto (pycrypto)

# How to Use

These scripts are rather simple and self-explanatory:

```
usage: argon-keygen.py [-h] -s STRING

optional arguments:
  -h, --help            show this help message and exit
  -s STRING, --string STRING
                        String to Hash
```

```
usage: cli-crypto-aes-cfb.py [-h] [-k KEY] [-r ROUNDS] [-e ENCRYPT | -d DECRYPT]

optional arguments:
  -h, --help            show this help message and exit
  -k KEY, --key KEY     key string
  -r ROUNDS, --rounds ROUNDS
                        number of hash cycles to apply to key string
  -e ENCRYPT, --encrypt ENCRYPT
                        string to encrypt
  -d DECRYPT, --decrypt DECRYPT
                        string to decrypt
```

There are two optional environment variables that can be set to help out:
* CLI_CRYPTO_KEY (arbitrary length string value)
* CLI_CRYPTO_ROUNDS (integer value)

## Fair Warning

Use at your own risk:
* Like any security-related product, you are assuming an unknown level of potential risk and liability.
* Neither warranty (expressed or implied) nor statement of suitability will be issued for these scripts.
* Never use any security or cryptography product without prior testing, knowledge of it's limitations and compliance with your preferred/required acceptance criteria.

## Built With

* [Python](https://www.python.org/) Designed by Guido van Rossum.

## Author

**Rick Pelletier**

## License

Copyright (C) 2022, Richard Pelletier

```
MIT License

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```
