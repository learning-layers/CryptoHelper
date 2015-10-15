# CryptoHelper

Minimal API for encrypting and decrypting strings.

## Gradle

This library can be retrieved from [jCenter](https://bintray.com/bintray/jcenter).

```groovy
compile 'fi.aalto.legroup:cryptohelper:0.1.0'
```

## Format

* Convert string to UTF-8 bytes
* Compute the CRC32 checksum of the UTF-8 bytes
* Prepend an 8 byte long containing the checksum to the UTF-8 data
* Generate a random initialization vector
* Transform the concatenated checksum and UTF-8 data with `AES/CBC/PKCS5Padding` using the generated IV
* Prepend the initialization vector to the encrypted data
* Base64 encode the concatenated IV and encrypted data

## License

```
Copyright 2013–2015 Aalto University

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```
