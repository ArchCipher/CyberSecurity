# <p align="center"> CTF Challenge: Linux & Security Concepts (OverTheWire: Wargames) </p>

**Platform:** OverTheWire  
**Objective:** Capture the flag/password to proceed to the next level  
**Skills & Tools:** Terminal, SSH, File Manipulation, Encoding/Decoding, Command-Line Utilities

---

## Overview
The **Bandit Wargames** are a series of challenges designed to teach fundamental cybersecurity concepts and Linux command-line skills. Each level introduces new tasks involving **file manipulation**, **access control**, **data encoding**, and **system navigation**.

I have completed **Level 18**. Levels 13-18 presented significant challenges involving **SSH connections**, **RSA private key authentication**, and **network communication protocols**, requiring deeper understanding of cryptographic concepts and remote access techniques.

Below is a walkthrough of the challenges I've completed so far, along with the techniques I used.

> _Alert: May contain spoilers!_

---

## Level 0
**Goal**: Connect to the server and read a file containing the password for the next level.

I started by connecting to the server using SSH:

`ssh <username>@<host_IP> -p <port>`

After logging in, I used `ls` to locate the file in the home directory and `cat` to view its contents.

---

## Level 1
**Goal**: Read a file with a dash (`-`) in its name.

The shell interprets a leading dash as an option. I could read the file using `./<filename>` or `-- <filename>`. The `--` tells the shell to stop interpreting anything after it as an option.

---

## Level 2
**Goal**: Read a file with spaces in its name.

Since spaces are interpreted as delimiters in the shell, I escaped them using backslash: `read\ the\ contents`

---

## Level 3
**Goal**: Find a hidden file.

Hidden files in Linux begin with a dot (`.`). I used the`-a` option with `ls` to list all files, including hidden ones, and used `cat` to read the file contents.

This step also reinforced the knowledge I gained from Google cybersecurity coursework.

---

## Level 4
**Goal**: Find the only human-readable file in a directory with various file types.

I used the `file` command to determine each file's type : `file *`. Then I filtered with `grep 'text'` to locate "ASCII text" files. It revealed a file that had a dash in its name, so I accessed it using `-- <filename>`.

---

## Level 5
**Goal**: Find a file with specific properties (human-readable, 1033 bytes, non-executable).

I initially used the `find` command with the `-size` option. There was only one match, so it was straightforward. I confirmed it wasn't executable by using `ls -l`.

However, a more accurate method for future levels would be to use `find` with `-size`, `! -perm`, `-exec file {} +`, filtering with `grep 'text'`. 

<details>
<summary><strong>Spoiler: Reveal Answer</strong></summary>
`find . -size <size_c> ! -perm -111 -exec file {} + | grep 'text'`
</details>

---

## Level 6
**Goal**: Locate a file located somewhere on the server, owned by a specific user and group with a specific file size.

I used `find` with `-user`, `-group`, and `-size` filters. Since I searched the root directory (`/`), I included the `-type f` option and redirected standard permission errors, i.e., file descriptor 2 (`2>`), to `/dev/null` which is a special file that discards all data written to it.

---

## Level 7
**Goal**: Find the password next to the word "millionth" in a file.

I used `grep` to search for the word "millionth" in the file, which revealed the password.

---

## Level 8
**Goal**: Find the only line in a file that occurs only once.

I used a combination of `sort` and `uniq` to filter repeated lines. But, this revealed several lines. So, I had to repeat with additional `uniq` option `-u` to isolate the unique line. 

---

## Level 9
**Goal**: Extract a human-readable string, preceded by several '=' characters, from a binary file.

I initially used `grep`, which returned a "binary file matches" message. So, I used the `strings` command to extract readable content, then piped it to `grep` to reveal the password.

---

## Level 10
**Goal**: Decode a base64-encoded file.

I combined `cat` and `base64 --decode` command to decode the password.

---

## Level 11
**Goal**: Decode a ROT13 (Caesar cipher) encoded message.

As 'A-Z' and 'a-z' were rotated 13 positions, i.e., A is N and Z is M. I used the `tr` command to decode the message.

Although the ROT13 cipher is a basic cipher, it served as an introduction to simple **cryptography**.

<details>
<summary><strong>Spoiler: Reveal Answer</strong></summary>
tr 'A-Za-z' 'N-ZA-Mn-za-m'
</details>

---

## Level 12
**Goal**: The password for the next level is stored in a file that has been repeatedly compressed and is represented as a **hexdump**. The challenge involves extracting and decompressing the file to reveal the password.

I started by creating a temporary directory using `mktemp -d` and copied the `data.txt` file there. The file was a hexdump, which began with the signature `1F 8B` for `Gzip (GNU zip)` and also had ASCII string `BZh` (magic number `42 5a 68`), indicating  `Bzip2`compression.

Using `xxd -r`, I converted it back into its binary form. The binary file was compressed multiple times using different formats, including **gzip**, **bzip2**, and **tar**.

I used the `file` command at each step to identify the compression format. After extracting the first layer, it revealed another compressed file, which required a different decompression method. This process was repeated multiple times until I reached a human-readable file containing the password.

I ran into an issue where `gunzip` didn't recognize some files as gzip-compressed unless they had a `.gz` extension. Since the files didn't have this extension, I renamed them each time to allow `gunzip` to detect and decompress them properly. This happens because `gunzip` relies on the `.gz` extension to identify gzip files.

This level further sharpened my understanding of working with compressed files and Linux utilities.

---
## Level 13
**Goal**: Retrieve the password for the next level using SSH key authentication instead of password authentication.

This level introduced **SSH key-based authentication**. Instead of receiving a password, I found a private SSH key that granted access to the next level. I used the `-i` (identity file) option with SSH to specify the private key file for authentication. Once connected, I located the password file that could only be accessed by the target user.

`ssh -i <privatekey_file> <username>@<hostname> -p <port>`

This level reinforced the concept of **public-key cryptography** and how SSH keys provide secure, password-free authentication.

---

## Level 14
**Goal**: Submit the current level's password to a specific port on localhost to retrieve the next password.

I used netcat (`nc`) to establish a **TCP connection** to the specified port and transmitted the password:

`echo "<password>" | nc <hostname> <port>`

This level introduced basic network communication and how services can listen on specific ports for data transmission.

---

## Level 15
**Goal**: Submit the current level's password using SSL/TLS encryption to retrieve the next password.

This challenge required establishing an **encrypted connection** using SSL/TLS. I used the `openssl s_client` command to create a secure connection to the specified port:

`openssl s_client -connect <hostname>:<port>`

This level demonstrated the difference between plain-text and encrypted network communications, emphasizing the importance of transport layer security.

---

## Level 16
**Goal**: Find the correct SSL/TLS enabled port within a specified range and submit the password to retrieve SSH credentials for the next level.

This level combined multiple concepts: **port scanning**, **service identification**, and **SSL/TLS communication**. I used `ss` (socket statistics) to identify listening ports within the specified range:

`ss -tln '( sport >= <start_port> and sport <= <end_port> )'`

The options `-tln` specify: show only TCP sockets, listening sockets, and don't resolve host/service names (show ports/IPs numerically). The syntax uses `sport` (source port) with comparison operators to filter ports within the range, demonstrating command-line filtering.

After identifying active ports, I tested each to determine which ones supported SSL/TLS encryption using:

`openssl s_client -connect <hostname>:<port> -quiet`

After the TLS handshake completed, I entered an interactive session with the server where I could send the password and receive responses. The `-quiet` flag was essential as it suppresses verbose connection information and diagnostic output (as documented in the `openssl s_client` man page under connected commands) - without it, the server's response would be cluttered with connection details, making it difficult to extract sensitive info like a private key.

The correct port returned an **RSA private key**. I saved this key to a temporary file and used it for SSH key authentication to access the next level. This challenge highlighted the importance of reconnaissance in cybersecurity.

---

## Level 17
**Goal**: Find the password by comparing two files and identifying the line that differs between them.

This level focused on **file comparison** and **data analysis**. I used command-line utilities to identify differences between two password files:

`sort <file1> <file2> | uniq -u`

This revealed the unique lines. I then used `grep` to determine which unique line belonged to the target file:

`grep "<unique_line>" <target_file>`

The challenge reinforced skills in text processing and pattern matching, essential for log analysis and forensic investigations in cybersecurity.

---

## Level 18
**Goal**: Retrieve the password from a file while bypassing a modified shell configuration that prevents normal login.

This challenge demonstrated **shell bypass techniques**. The `.bashrc` file was modified to automatically log out users, preventing normal interactive sessions. Investigation revealed the file contained `exit 0` commands that forced logout upon login. I used SSH command execution to retrieve the file contents without entering an interactive shell.

`ssh -t <username>@<hostname> -p <port> "cat <filename>"`

The `-t` flag forces allocation of a pseudo-terminal, which tricks the server into treating the session as interactive — useful when the shell tries to auto-logout.

This showcased how attackers might bypass security restrictions. The level emphasized the importance of understanding **shell behavior** and **remote command execution** in both offensive and defensive security contexts.

---

## Conclusion

This experience has definitely improved my **command-line skills** and my understanding of how to navigate and analyze systems securely. 

---