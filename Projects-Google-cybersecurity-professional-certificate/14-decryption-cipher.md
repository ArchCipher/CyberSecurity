# <p align="center"> Decryption with OpenSSL: Caesar to AES </p>

## Project Overview

In this project, all the files in my home directory were encrypted. I used Linux commands to break a Caesar cipher and decrypt the files, allowing me to read the hidden messages they contained.

---

# Process

```bash
ls
# Output:
# Q1.encrypted  README.txt  caesar

cat README.txt  # Read the instruction file
# Output:
# Hello,
# All of your data has been encrypted. To recover your data, you will need to solve a cipher. To get started look for a hidden file in the caesar subdirectory.

ls -a caesar    # Check the contents of the 'caesar' subdirectory
# Output:
#.  ..  .leftShift3

cd caesar   # Change into the 'caesar' directory

cat .leftShift3  # Read the encrypted file
# Output:
# Lq rughu wr uhfryhu brxu ilohv brx zloo qhhg wr hqwhu wkh iroorzlqj frppdqg:
# rshqvvo dhv-256-fef -sengi2 -d -g -lq T1.hqfubswhg -rxw T1.uhfryhuhg -n hwwxeuxwh

# Decrypt the Caesar cipher using the `tr` command with a left shift of 3 characters
cat .leftShift3 | tr "d-za-cD-ZA-C" "a-zA-Z"    # used translate characters command to decrypt
# Output:
# In order to recover your files you will need to enter the following command:
# openssl aes-256-cbc -pbkdf2 -a -d -in Q1.encrypted -out Q1.recovered -k ettubrute

# Attempted the command in the wrong directory (missing input file)
openssl aes-256-cbc -pbkdf2 -a -d -in Q1.encrypted -out Q1.recovered -k ettubrute
# Output:
# Can't open Q1.encrypted for reading, No such file or directory

cd ../  # Return to the home directory

# Correct command to decrypt the file using OpenSSL:
openssl aes-256-cbc -pbkdf2 -a -d -in Q1.encrypted -out Q1.recovered -k ettubrute   # extract decrypted file
```

**Explanation:**

Syntax: `openssl aes-256-cbc -pbkdf2 -a -d -in <input> -out <output> -k <password>`

`aes-256-cbc`: AES encryption algorithm with a 256-bit key in CBC (Cipher Block Chaining) mode.

`-pbkdf2`: Uses the PBKDF2 (Password-Based Key Derivation Function 2) algorithm to derive the encryption key from the provided password. Adds key stretching for improved security.

`-a` or `-base64`: Base64 encodes the input data before encryption or decodes it after decryption. This is useful for handling binary data in text-based formats.

`-d`: Decrypts the input file. Without this option, the command would encrypt the data.

`-in <input>`: The input file to be decrypted.

`-out <output>`: The output file for the decrypted data.

`-k <password>`: The decryption password

```bash
ls
# Output:
# Q1.encrypted  Q1.recovered  README.txt  caesar

cat Q1.recovered    # Read the decrypted file
# Output:
# If you are able to read this, then you have successfully decrypted the classic cipher text. You recovered the encryption key that was used to encrypt this file. Great work!

```
---

# Reflection

In the OverTheWire: Bandit CTF challenge, I encountered tasks involving both basic and advanced encryption. I used the `tr` command to solve a ROT13 decryption task and `openssl s_client -connect localhost:<port`> to interact with SSL/TLS services over SSH.

This project was my first time using OpenSSL for local file decryption with AES. It expanded my understanding of OpenSSL from network-level encryption to file-level symmetric encryption and decryption.

The experience highlighted the importance of understanding both simple ciphers like Caesar and modern standards like AES-256 — especially in layered or real-world security challenges.

---