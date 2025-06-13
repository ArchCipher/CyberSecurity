# <p align="center"> Linux Authorization and Least Privilege Hardening </p>

## Project Overview

I simulated the role of a cybersecurity analyst, I was tasked with auditing and correcting file and directory permissions in the `projects/` directory used by the research team. The permissions did not reflect the intended access control policy, which posed a security risk. I performed a detailed audit and adjusted permissions in accordance with the principle of least privilege.

## Objectives

* Check existing file and directory permissions
* Remove unauthorized access to a files and directories
* Apply correct access permissions using `chmod`
* Ensure hidden files and directories were also secured

## Audit Process
Used the following command to list file and directory details, including hidden files:

```bash
ls -la ~/projects
```

Output:
```bash
total 32
drwxr-xr-x 3 researcher2 research_team 4096 Jun 11 13:55 .
drwxr-xr-x 3 researcher2 research_team 4096 Jun 11 14:45 ..
-rw--w---- 1 researcher2 research_team   46 Jun 11 13:55 .project_x.txt
drwx--x--- 2 researcher2 research_team 4096 Jun 11 13:55 drafts
-rw-rw-rw- 1 researcher2 research_team   46 Jun 11 13:55 project_k.txt
-rw-r----- 1 researcher2 research_team   46 Jun 11 13:55 project_m.txt
-rw-rw-r-- 1 researcher2 research_team   46 Jun 11 13:55 project_r.txt
-rw-rw-r-- 1 researcher2 research_team   46 Jun 11 13:55 project_t.txt
```

Key Observations:
* File/directory type and permission string (ex: `-rw-rw-rw-`)

* Ownership (user `researcher2` and group `research_team`)

* Visibility of hidden files (prefixed with `.`)

## Understanding Permission Strings
A typical 10-character permission string (ex: `-rwxrw-r--`) breaks down as:

* `-`: regular file (`d` for directories)

* `rwx`: user permissions (read/write/execute)

* `rw-`: group permissions (read/write)

* `r--`: other users (read only)

This format helped identify files with overly permissive access.

## Security Fixes Implemented
I used the following commands to enforce correct permissions:

```bash
chmod o-w project_k.txt
chmod g-r project_m.txt
chmod u-w,g-w+r .project_x.txt
chmod g-x drafts
```
1. Removed 'write' access for 'other' on `project_k.txt`

2. Removed 'read' access for 'group' on `project_m.txt`

3. Secured hidden file `.project_x.txt` by making it read-only to 'user' and 'group'

4. Restricted 'group' access to `drafts/` directory, leaving only the 'user' with execute rights

## Result
Verified updated permissions with:

```bash
ls -la
```

Output:
```bash
total 32
drwxr-xr-x 3 researcher2 research_team 4096 Jun 11 13:55 .
drwxr-xr-x 3 researcher2 research_team 4096 Jun 11 14:45 ..
-r--r----- 1 researcher2 research_team   46 Jun 11 13:55 .project_x.txt
drwx------ 2 researcher2 research_team 4096 Jun 11 13:55 drafts
-rw-rw-r-- 1 researcher2 research_team   46 Jun 11 13:55 project_k.txt
-rw------- 1 researcher2 research_team   46 Jun 11 13:55 project_m.txt
-rw-rw-r-- 1 researcher2 research_team   46 Jun 11 13:55 project_r.txt
-rw-rw-r-- 1 researcher2 research_team   46 Jun 11 13:55 project_t.txt
```

Changes ensured:
* All permissions now align with least-privilege principles

* No unauthorized write or execute access remains

* Hidden files and sensitive directories are properly secured

* Access control complies with organizational security policy

## Reflection
This task went beyond simple file management—it reinforced the importance of **access control, auditing, and securing sensitive assets**. Understanding and enforcing Linux file permissions is a critical part of maintaining system security posture.

---