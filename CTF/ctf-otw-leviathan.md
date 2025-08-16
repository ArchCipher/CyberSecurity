# <p align="center"> CTF Challenge: Binary Analysis & Reverse Engineering (OverTheWire: Leviathan) </p>

**Platform:** OverTheWire  
**Objective:** Capture the flag/password to proceed to the next level through binary analysis and reverse engineering

---

## Skills Demonstrated & Tools Used
- **Binary Analysis**: Setuid binaries, ELF analysis, function tracing, debugging tools (ltrace, strace, gdb, objdump, strings, nm, readelf, hexdump), shell scripting, system call analysis

---

## Overview
The **Leviathan Wargames** are a series of challenges designed to teach binary analysis and reverse engineering concepts. Each level introduces new tasks involving **setuid binaries**, **function tracing**, **debugging tools**, and **privilege escalation**.

I have completed **Level 2**. Levels 0-2 presented challenges involving **binary analysis**, **function tracing**, **debugging tools**, and **input validation bypass**, requiring understanding of C library functions, system calls, and reverse engineering techniques.

Below is a walkthrough of the challenges I've completed, along with the techniques I used.

---

## Level 0 - File Discovery and Information Extraction
**Goal**: Find the password by exploring the home directory and examining accessible files.

I connected via SSH and used `ls -a` to discover hidden files. Found a `.backup` directory containing `bookmarks.html`. Used `grep` to extract the password from the HTML file.

---

## Level 1 - Function Tracing and Input Validation Bypass
**Goal**: Analyze a binary to understand its password validation mechanism.

I used `ltrace ./check` to trace C library function calls and discovered the binary used `strcmp()` to compare input with the actual password "sex". The function revealed the password through string comparison analysis.

**Challenges and Learnings:**
- Initially tried brute force scripting with nested loops for 4-character and 10-character combinations. Used background processes (`&`) and output redirection to manage long-running scripts
- Learned that `ltrace` traces library calls while `strace` traces system calls
- Discovered that `strcmp()` returns 0 for equal strings, making it easy to identify the correct password

---

## Level 2 - Setuid Binary Analysis
**Goal**: Analyze a setuid binary to understand its file access restrictions.

I examined the `printfile` binary using `file` command and discovered it was a setuid ELF executable. The binary restricted access to `/etc/leviathan_pass/` files. Used various debugging tools to analyze the binary structure.

**Challenges and Learnings:**
- Learned about unstripped binaries containing function names, variable names, and symbol tables
- Discovered useful debugging tools: `strace`, `ltrace`, `gdb`, `objdump`, `strings`, `nm`, `readelf`, `hexdump`, `xxd`
- Understood the difference between system calls (kernel interface) and library calls (libc)

**Status:** Not yet solved

---
