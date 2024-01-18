# EFC (Easy File Crypt)

EFC is a user-friendly application, crafted in C++17, that specializes in the encryption
and decryption of files. The only prerequisite for encrypting or decrypting a file is a password.

## Build

To successfully build the project, follow these steps:

1. Ensure that you have CMake and a compiler known to CMake properly installed.
2. Clone the repository using the following command:

```bat
git clone https://github.com/MateuszJanduraUszu/EFC.git
```

3. Build the `efc` executable:

```bat
cd build\cmake
build.bat {x64|Win32} "{Compiler}"
```

These steps will help you compile the project's executable using the specified platform
architecture and compiler.

## Installation and uninstallation

The EFC application is designed for immediate use, requiring no installation or
uninstallation process. It becomes operational as soon as it is unpacked.
If you no longer need the application, simply remove the directory where EFC resides.

## Usage

EFC provides the following command-line options for your convenience:
* `--help` - Presents a guide on how to use the application.
* `--encrypt` - Prepares the application for the encryption process.
* `--decrypt` - Prepares the application for the decryption process.
* `--path="<absolute-path>"` - Defines the absolute path of the file to be encrypted or decrypted.
* `--password="<password>"` - Sets the password to be utilized during the encryption or decryption process.

## Examples

- To display help:

```bat
efc.exe --help
```

- To encrypt a file:

```bat
efc.exe --encrypt --path="C:\Program Files (x86)\Directory\File.txt" --password="My very secure password"
```

- To decrypt a file:

```bat
efc.exe --decrypt --path="C:\Program Files (x86)\Directory\File.txt.efc" --password="My very secure password"
```

## How it works

EFC stores less sensitive information such as the salt, IV and authentication tag directly
within the file metadata. The most critical component, the key, is not stored but rather dynamically
generated at runtime. This key is derived from the user-specified password using the Argon2id
key-derivation algorithm. This approach ensures the security of the key and, consequently, the encrypted data.

The password, which should be both lengthy and random, must not exceed 63 characters.
Even if no Unicode characters are specified, the password is processed as Unicode.

The application employs the AES-256-GCM cipher to guarantee secure encryption and decryption.
An authentication tag safeguards this process, ensuring data integrity during decryption.

Remember, the security of your data is contingent on the strength of your password.
Therefore, choose your password wisely.

## Compatibility

EFC is designed to be compatible with any Windows version that supports the Botan, OpenSSL and MJ modules.
The application minimizes the use of version-specific features to maximize cross-version compatibility.
However, for optimal performance, it is recommended to use it on Windows XP or later versions.

## Questions and support

If you have any questions, encounter issues, or need assistance with the File Shredder
application, feel free to reach out. You can reach me through the `Issues` section
or email ([mjandura03@gmail.com](mailto:mjandura03@gmail.com)).

## Licence

Copyright © Mateusz Jandura.

SPDX-License-Identifier: Apache-2.0