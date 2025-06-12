# CTF Challenge: Security Concepts (OverTheWire: Wargames)

**Platform:** OverTheWire  
**Objective:** Capture the flag/password to proceed to the next level  
**Skills Used:** Terminal, SSH, File Manipulation, Encoding/Decoding, and Command-Line Utilities

## What I Did:
Here’s a breakdown of the steps I followed to complete the **Bandit Wargames** challenge:

### Level 0
Connected to the OverTheWire server via `SSH` and read a file containing the first password.

### Level 1
Accessed a file with a dash "-" in its name.

### Level 2
Accessed a file with spaces in its name.

### Level 3
Accessed hidden files

### Level 4
Filtered to find the only human-readable file in a directory and accessed it. The file had a dashed filename.
**Commands Used**: `file`, `grep`, `cat`

### Level 5
Found the file that met the conditions: human-readable, specific size, and non-executable.
**Commands Used**: `find`, `file`, `grep`

### Level 6
Found the file from the root directory based on ownership and size, and redirected `stderr` to `/dev/null`.  
**Commands Used**: `find`

### Level 7
Searched for a line containing a specific word in a file.
**Command Used**: `grep`

### Level 8
Searched for a line that occurred only once in a file.
**Commands Used**: `sort`, `uniq`

### Level 9
Extracted the only human-readable string from a binary file.
**Commands Used**: `strings`, `grep`

### Level 10
Decoded a file with a base64 string to reveal the password.  
**Command Used:** `base64`

### Level 11
Decoded a file with a ROT13 (Caesar cipher) message.  
**Command Used**: `tr`

## **Outcome:**
- Gained hands-on experience using the **CLI** and **SSH**.
- Developed practical skills in **file manipulation**, **shell commands**, and **security concepts** such as encoding/decoding, hidden files, and text processing.
- Successfully completed **Bandit Level 12** by solving challenges related to cybersecurity fundamentals.

---