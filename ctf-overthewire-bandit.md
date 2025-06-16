# <p align="center"> CTF Challenge: Linux & Security Concepts (OverTheWire: Wargames) </p>

**Platform:** OverTheWire  
**Objective:** Capture the flag/password to proceed to the next level  
**Skills & Tools:** Terminal, SSH, File Manipulation, Encoding/Decoding, Command-Line Utilities

---

## **Overview**
The **Bandit Wargames** are a series of challenges designed to teach fundamental cybersecurity concepts and Linux command-line skills. Each level introduces new tasks involving **file manipulation**, **access control**, **data encoding**, and **system navigation**.

I am currently on **Level 13**. Level 12 introduced a new challenge of repeatedly decompressing files represented as a hexdump. I had to identify the compression formats (gzip, bzip2, tar), and carefully extract each layer until I reached a human-readable file containing the password. 

Below is a walkthrough of the challenges I've completed so far, along with the techniques I used.

> _Alert: May contain spoilers!_

---

## **Level 0**
**Goal**: Connect to the server and read a file containing the password for the next level.

I started by connecting to the server using SSH:

`ssh <username>@<host_IP> -p <port>`

After logging in, I used `ls` to locate the file in the home directory and `cat` to view its contents.

---

## **Level 1**
**Goal**: Read a file with a dash (`-`) in its name.

The shell interprets a leading dash as an option. I could read the file using `./<filename>` or `-- <filename>`. The `--` tells the shell to stop interpreting anything after it as an option.

---

## **Level 2**
**Goal**: Read a file with spaces in its name.

Since spaces are interpreted as delimiters in the shell, I escaped them using backslash: `read\ the\ contents`

---

## **Level 3**
**Goal**: Find a hidden file.

Hidden files in Linux begin with a dot (`.`). I used the`-a` option with `ls` to list all files, including hidden ones, and used `cat` to read the file contents.

This step also reinforced the knowledge I gained from Google cybersecurity coursework.

---

## **Level 4**
**Goal**: Find the only human-readable file in a directory with various file types.

I used the `file` command to determine each file's type : `file *`. Then I filtered with `grep 'text'` to locate "ASCII text" files. It revealed a file that had a dash in its name, so I accessed it using `-- <filename>`.

---

## **Level 5**
**Goal**: Find a file with specific properties (human-readable, 1033 bytes, non-executable).

I initially used the `find` command with the `-size` option. There was only one match, so it was straightforward. I confirmed it wasn’t executable by using `ls -l`.

However, a more accurate method for future levels would be to use `find` with `-size`, `! -perm`, `-exec file {} +`, filtering with `grep 'text'`. 

<details>
<summary><strong>Spoiler: Reveal Answer</strong></summary>
`find . -size <size_c> ! -perm -111 -exec file {} + | grep 'text'`
</details>

---

## **Level 6**
**Goal**: Locate a file located somewhere on the server, owned by a specific user and group with a specific file size.

I used `find` with `-user`, `-group`, and `-size` filters. Since I searched the root directory (`/`), I included the `-type f` option and redirected standard permission errors, i.e., file descriptor 2 (`2>`), to `/dev/null` which is a special file that discards all data written to it.

---

## **Level 7**
**Goal**: Find the password next to the word “millionth” in a file.

I used `grep` to search for the word “millionth” in the file, which revealed the password.

---

## **Level 8**
**Goal**: Find the only line in a file that occurs only once.

I used a combination of `sort` and `uniq` to filter repeated lines. But, this revealed several lines. So, I had to repeat with additional `uniq` option `-u` to isolate the unique line. 

---

## **Level 9**
**Goal**: Extract a human-readable string, preceded by several ‘=’ characters, from a binary file.

I initially used `grep`, which returned a "binary file matches" message. So, I used the `strings` command to extract readable content, then piped it to `grep` to reveal the password.

---

## **Level 10**
**Goal**: Decode a base64-encoded file.

I combined `cat` and `base64 --decode` command to decode the password.

---

## **Level 11**
**Goal**: Decode a ROT13 (Caesar cipher) encoded message.

As 'A-Z' and 'a-z' were rotated 13 positions, i.e., A is N and Z is M. I used the `tr` command to decode the message.

Although the ROT13 cipher is a basic cipher, it served as an introduction to simple **cryptography**.

<details>
<summary><strong>Spoiler: Reveal Answer</strong></summary>
tr 'A-Za-z' 'N-ZA-Mn-za-m'
</details>

---

## **Level 12**
**Goal**: The password for the next level is stored in a file that has been repeatedly compressed and is represented as a **hexdump**. The challenge involves extracting and decompressing the file to reveal the password.

I started by creating a temporary directory using `mktemp -d` and copied the `data.txt` file there. The file was a hexdump, which began with the signature `1F 8B` for `Gzip (GNU zip)` and also had ASCII string `BZh` (magic number `42 5a 68`), indicating  `Bzip2`compression.

Using `xxd -r`, I converted it back into its binary form. The binary file was compressed multiple times using different formats, including **gzip**, **bzip2**, and **tar**.

I used the `file` command at each step to identify the compression format. After extracting the first layer, it revealed another compressed file, which required a different decompression method. This process was repeated multiple times until I reached a human-readable file containing the password.

I ran into an issue where `gunzip` didn’t recognize some files as gzip-compressed unless they had a `.gz` extension. Since the files didn’t have this extension, I renamed them each time to allow `gunzip` to detect and decompress them properly. This happens because `gunzip` relies on the `.gz` extension to identify gzip files.

This level further sharpened my understanding of working with compressed files and Linux utilities.

---

## **Conclusion**

This experience has definitely improved my **command-line skills** and my understanding of how to navigate and analyze systems securely. 

---