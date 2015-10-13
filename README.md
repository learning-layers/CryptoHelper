# CryptoHelper

Minimal API for encrypting and decrypting strings.

## Format

* Convert string to UTF-8 bytes
* Compute the CRC32 checksum of the UTF-8 bytes
* Prepend an 8 byte long containing the checksum to the UTF-8 data
* Generate a random initialization vector
* Transform the concatenated checksum and UTF-8 data with `AES/CBC/PKCS5Padding` using the generated IV
* Prepend the initialization vector to the encrypted data
* Base64 encode the concatenated IV and encrypted data
