# <p align="center"> CTF Challenge: Binary Analysis & Reverse Engineering (OverTheWire: Leviathan) </p>

**Platform:** OverTheWire  
**Objective:** Capture the flag/password to proceed to the next level through binary analysis and reverse engineering

---

## Skills Demonstrated
- **Binary Analysis**: Setuid binaries, ELF analysis, function tracing, debugging tools, shell scripting, system call analysis
- **Reverse Engineering**: Assembly code analysis, memory inspection, register examination, stack frame analysis
- **Privilege Escalation**: Setuid exploitation, symbolic link manipulation, file access bypass
- **Data Encoding**: Binary to ASCII conversion, octal/hexadecimal manipulation, base conversion
- **Debugging**: Breakpoint setting, memory inspection, register analysis, stack frame navigation

## Tools Used
- **Debugging Tools**: gdb, ltrace, strace, objdump, nm, readelf
- **Binary Analysis**: file, strings, hexdump, xxd
- **System Commands**: ln, cat, ls, whoami, groups
- **Data Conversion**: bc, printf, tr, bash arithmetic
- **Shell Scripting**: for loops, while loops, command substitution

---

## Overview
The **Leviathan Wargames** are a series of challenges designed to teach binary analysis and reverse engineering concepts. Each level introduces new tasks involving **setuid binaries**, **function tracing**, **debugging tools**, and **privilege escalation**.

I have completed **Level 7**. Levels 0-7 presented challenges involving **binary analysis**, **function tracing**, **debugging tools**, **input validation bypass**, **symbolic link exploitation**, **data encoding**, and **assembly code analysis**, requiring understanding of C library functions, system calls, reverse engineering techniques, and low-level programming concepts.

Below is a walkthrough of the challenges I've completed, along with the techniques I used.

---

## Level 0 - File Discovery and Information Extraction
**Goal**: Find the password by exploring the home directory and examining accessible files.

I connected via SSH and used `ls -a` to discover hidden files. Found a `.backup` directory containing `bookmarks.html`. Used `grep` to extract the password from the HTML file.

---

## Level 1 - Function Tracing and Input Validation Bypass
**Goal**: Analyze a binary to understand its password validation mechanism.

I used `ltrace ./check` to trace C library function calls and discovered the binary used `strcmp()` to compare input with the actual password. The function revealed the password through string comparison analysis.

**Challenges and Learnings:**
- Initially tried brute force scripting with nested loops for 4-character and 10-character combinations. Used background processes (`&`) and output redirection to manage long-running scripts
- Learned that `ltrace` traces library calls while `strace` traces system calls
- Discovered that `strcmp()` returns 0 for equal strings, making it easy to identify the correct password
- Understood the difference between system calls (kernel interface) and library calls (libc)

---

## Level 2 - Setuid Binary Analysis and Symbolic Link Exploitation
**Goal**: Analyze a setuid binary to understand its file access restrictions and exploit them.

I examined the `printfile` binary using `file` command and discovered it was a setuid ELF executable. The binary restricted access to `/etc/leviathan_pass/leviathan3` file. Used various debugging tools to analyze the binary structure and discovered a path traversal vulnerability.

**Challenges and Learnings:**
- Learned about unstripped binaries containing function names, variable names, and symbol tables
- Discovered useful debugging tools: `strace`, `ltrace`, `gdb`, `objdump`, `strings`, `nm`, `readelf`, `hexdump`, `xxd`
- Understood the difference between system calls (kernel interface) and library calls (libc)
- The binary used `snprintf("/bin/cat %s", filename)` to construct a command string, which created a path traversal vulnerability when filenames contained spaces
- Initially tried using a symbolic link directly with `ln -s /etc/leviathan_pass/leviathan3 /tmp/foo`, but the access check failed
- Created a file with a space in the name like `foo bar` where `foo` was a symbolic link to the target file, allowing the access check to pass while `cat` would read the linked file
- The `cat` command read the first part (the linked file content) but then failed on the second part (the non-existent "bar" file), which was expected behavior

**Technical Analysis:**
```bash
ltrace ./printfile .bash_logout
__libc_start_main(0x80490ed, 2, 0xffffd444, 0 <unfinished ...>
access(".bash_logout", 4)                                = 0
snprintf("/bin/cat .bash_logout", 511, "/bin/cat %s", ".bash_logout") = 21
geteuid()                                                = 12002
geteuid()                                                = 12002
setreuid(12002, 12002)                                   = 0
system("/bin/cat .bash_logout"...
```

The vulnerability was in the `snprintf("/bin/cat %s", filename)` call that constructed the command string. When a filename contained spaces, it would be passed as separate arguments to `cat`, allowing exploitation through symbolic links.

---

## Level 3 - Function Tracing and Password Discovery
**Goal**: Analyze a binary to discover the password through function tracing.

I used `ltrace ./level3` to trace function calls and discovered the binary was comparing input with a hardcoded password using `strcmp()`. This was similar to Level 1 and straightforward to solve.

---

## Level 4 - Binary Data Analysis and ASCII Conversion
**Goal**: Execute a binary file and convert its binary output to ASCII to find the password.

I found a binary executable in the `.trash` directory that output binary data. I needed to convert this binary data to ASCII to extract the password.

**Challenges and Learnings:**
- Learned several ways to convert binary to ASCII including using `bc` and `printf` with octal escapes, bash arithmetic with `printf`, and hexadecimal conversion methods
- Understood the Binary → Decimal → Octal → ASCII conversion process and how printf interprets different escape sequences
- Used three different methods for binary to ASCII conversion:
  - Method 1: Using `bc` and `printf` with octal escapes: `echo 00110000 01100100 ... | tr ' ' '\n' | while read byte; do printf "\\$(echo "ibase=2; obase=8; $byte" | bc)"; done;`
  - Method 2: Using bash arithmetic with `printf`: `for b in 00110000 01100100 ...; do printf "\\$(printf '%o' $((2#$b)))"; done;`
  - Method 3: Using hexadecimal conversion: `for b in 00110000 01100100 ...; do printf "\\x$(printf '%x' $((2#$b)))"; done; echo`
- Learned that `2#$b` is bash arithmetic syntax for parsing binary numbers, `printf '%o'` converts decimal to octal, and `printf "\\ooo"` interprets octal values as ASCII characters
- Understood that octal escapes use `\NNN` format (e.g., \060 → '0') and hexadecimal escapes use `\xNN` format (e.g., \x30 → '0')

---

## Level 5 - Symbolic Link Exploitation
**Goal**: Analyze a binary that reads from a specific file and exploit it using symbolic links.

I used `ltrace ./leviathan5` to discover that the binary was trying to read from a nonexistent file `/tmp/file.log`. I created a symbolic link to redirect this file access to the password file, using the same technique learned from Level 2.

---

## Level 6 - Assembly Code Analysis and Memory Inspection
**Goal**: Analyze a binary that requires a 4-digit code and find the correct value through debugging.

I used `ltrace` and `strace` to analyze the binary's behavior, then used `gdb` to inspect memory and registers to find the expected value.

**Challenges and Learnings:**
- Initially tried to understand the `getrandom()` system calls from `strace` output, thinking the random values were related to the password, but realized they were just for randomization and not the actual comparison value
- Initially tried `gdb ./leviathan6` and `disas main` without arguments, which was not the right approach since the program needed arguments to run properly, then used the following GDB script to debug the binary:

```bash
gdb --args leviathan6 0000
(gdb) disas main                    # Find comparison instruction
(gdb) break *(address of cmp)       # Set breakpoint at cmp instruction  
(gdb) run                          # Run program to breakpoint
(gdb) info registers               # Examine register contents
(gdb) print $ebp-0xc               # Get address of local variable
(gdb) x (address from previous)    # Examine memory at that address
(gdb) print/d (address)            # Convert hex to decimal
```

- As a learning exercise, also systematically inspected memory at different offsets (`ebp-0x4`, `ebp-0x8`) to understand stack frame layout and how local variables are accessed relative to `ebp` at negative offsets, where `ebp` is the base pointer serving as a fixed reference point and local variables are accessed at negative offsets like `ebp-0xc` (12 bytes below the base pointer)

**Alternative Solution:**
The challenge could also be solved through brute force:
```bash
for i in $(seq -w 0000 9999); do ./leviathan6 $i; done
# or
for i in {0000..9999}; do ./leviathan6 $i; done
```

---

## Level 7 - Completion
**Goal**: Access the final level and read the congratulations message.

I successfully accessed the final level and found the congratulations message indicating completion of the Leviathan challenges.

---

## Key Learning Outcomes

The Leviathan challenges provided comprehensive training in binary analysis and reverse engineering. Key takeaways include the importance of systematic analysis, the power of debugging tools, and the need to understand both high-level programming concepts and low-level system behavior. The challenges also highlighted common security vulnerabilities in binary applications and how they can be exploited through careful analysis and understanding of program behavior.

---

## Conclusion

The Leviathan challenges provided comprehensive training in binary analysis and reverse engineering. From basic function tracing to complex assembly code analysis, each level built upon previous knowledge while introducing new concepts and techniques. The progression demonstrates the depth of knowledge required for effective binary reverse engineering and highlights common security vulnerabilities in binary applications.
