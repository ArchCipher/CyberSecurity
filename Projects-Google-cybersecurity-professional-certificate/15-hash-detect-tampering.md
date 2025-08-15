# <p align="center"> Digital Forensics & File Integrity Analysis </p>

## Project Overview

In this lab activity, I created SHA-256 hash values for two files and used Linux commands to manually examine differences. I investigated whether the files were truly identical or if subtle alterations existed.

---

# Process

```bash
ls 
# Output:
# file1.txt  file2.txt

cat file1.txt
# Output:
# X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*

cat file2.txt
# Output:
# X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*

sha256sum file1.txt     # Generate hash value
# Output:
# 131f95c51cc819465fa1797f6ccacf9d494aaaff46fa3eac73ae63ffbdfd8267  file1.txt

sha256sum file2.txt     # Generate hash value
# Output:
# 2558ba9a4cad1e69804ce03aa2a029526179a91a5e38cb723320e83af9ca017b  file2.txt

sha256sum file1.txt >> file1hash    # Save file1 hash to file
sha256sum file2.txt >> file2hash    # Save file2 hash to file

cat file1hash   # Read hash value
# Output:
# 131f95c51cc819465fa1797f6ccacf9d494aaaff46fa3eac73ae63ffbdfd8267  file1.txt

cat file2hash   # Read hash value
# Output:
# 2558ba9a4cad1e69804ce03aa2a029526179a91a5e38cb723320e83af9ca017b  file2.txt

cmp file1hash file2hash     # Compare hash values
# Output:
# file1hash file2hash differ: char 1, line 1
```
The output of the `cmp` command confirms a difference starting at character 1 of line 1 in the hash files. 

## Extended analysis

```bash
file file1.txt 
# Output:
# file1.txt: EICAR virus test files

file file2.txt
# Output:
# file2.txt: EICAR virus test files

# The 'file' command identifies file type but not encoding.
file -i file1.txt   # check encoding
# Output:
# file1.txt: text/plain; charset=us-ascii
file -i file2.txt   # force check encoding
# Output:
# file2.txt: text/plain; charset=us-ascii
```

There is no difference in file encoding.

```bash
stat file1.txt  # detect metadata differences
# Output:
#   File: file1.txt
#  Size: 69              Blocks: 8          IO Block: 4096   regular file
#Device: 2eh/46d Inode: 32648       Links: 1
#Access: (0644/-rw-r--r--)  Uid: (    0/    root)   Gid: (    0/    root)
#Access: 2025-06-20 05:57:20.737194774 +0000
#Modify: 2025-06-20 05:40:38.692771834 +0000
#Change: 2025-06-20 05:40:38.692771834 +0000
# Birth: -

stat file2.txt  # detect metadata differences
# Output:
#   File: file2.txt
#  Size: 79              Blocks: 8          IO Block: 4096   regular file
#Device: 2eh/46d Inode: 32656       Links: 1
#Access: (0644/-rw-r--r--)  Uid: (    0/    root)   Gid: (    0/    root)
#Access: 2025-06-20 05:57:28.733748455 +0000
#Modify: 2025-06-20 05:40:38.872784327 +0000
#Change: 2025-06-20 05:40:38.872784327 +0000
# Birth: -
```
File metadata shows that the two files differ in size, timestamps, and inode (index node) numbers. However, SHA-256 hash values are not influenced by metadata — they reflect content only.

```bash
diff -y <(cat -A file1.txt) <(cat -A file2.txt)     # cat -vet or cat -A shows special characters like ^X, newlines, tabs
# Output:
# X5O!...-FIL   X5O!...-FIL
                                                              
# > 9sxa5Yq20Ranal
```
The `cat -A` command shows that `file2.txt` includes extra hidden content (`9sxa5Yq20Ranal`) not present in `file1.txt`.

If the difference is still unclear, use:

```bash
diff -y <(xxd file1.txt) <(xxd file2.txt)   # Side-by-side hex comparison

hexdump -C file1.txt    # view byte structure
xxd file1.txt   # view byte structure
```
These tools show the byte-level differences in the files.

Preprocessing means converting the file into a more analyzable format (like hex or visible symbols) before comparison. `diff` shows line-level changes; `cmp` compares byte-by-byte.

---

## Summary

Although the visible content appeared identical in both files, they may still be different at a binary level. Using `cat -A` and `diff -y`, I discovered that `file2.txt` contained extra hidden characters: `9sxa5Yq20Ranal` beyond the standard EICAR test string. This demonstrates how even subtle or invisible changes to file content can be critical in file integrity and malware detection analysis.

---

## Notes
EICAR (European Institute for Computer Antivirus Research) developed a standard test file used to safely test the behavior of antivirus software without using real malware.

The EICAR test string is:

`X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*`

**Ways to detect how the files are different**:
Use `file` to check encoding/file type, use `stat` to check metadata, use `cat -A`, `hexdump` or `xxd` with `diff` to detect invisible characters or to view byte structure.

---