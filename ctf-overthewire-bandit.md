# <p align="center"> CTF Challenge: Linux & Security Concepts (OverTheWire: Wargames) </p>

**Platform:** OverTheWire  
**Objective:** Capture the flag/password to proceed to the next level

---

## Skills Demonstrated
- **SSH and Remote Access**: Secure shell connections, key-based authentication
- **File System Navigation**: Linux directory structure, hidden files, permissions
- **Text Processing**: Pattern matching, filtering, sorting, and data extraction
- **Network Protocols**: TCP connections, SSL/TLS encryption, port scanning
- **Binary Analysis**: File type identification, hexdump analysis, string extraction
- **Git Operations**: Repository cloning, commit history analysis, branch exploration
- **Shell Scripting**: Automation, loop constructs, error handling
- **Privilege Escalation**: Setuid binaries, restricted shell bypass techniques
- **Cryptographic Concepts**: Encoding/decoding, encryption, key management

## Tools Used
- **Network Tools**: SSH, netcat (nc), openssl s_client, ss
- **File Analysis**: file, strings, xxd, hexdump
- **Text Processing**: grep, sort, uniq, cut, tr, base64
- **File Operations**: find, ls, cat, cp, mv, tar, gunzip, bunzip2
- **Version Control**: git (clone, log, show, checkout, branch, tag, push)
- **System Analysis**: timeout
- **Shell**: Bash scripting, heredocs, variable manipulation

---

## Overview
The **Bandit Wargames** are a series of challenges designed to teach fundamental cybersecurity concepts and Linux command-line skills. Each level introduces new tasks involving **file manipulation**, **access control**, **data encoding**, and **system navigation**.

I have completed **Level 32**. Levels 13-32 presented significant challenges involving **SSH connections**, **RSA private key authentication**, **network communication protocols**, **Git security**, and **shell restriction bypasses**, requiring deeper understanding of cryptographic concepts and remote access techniques.

Below is a walkthrough of the challenges I've completed, along with the techniques I used.

---

## Level 0 - SSH Login and Read Password
**Goal**: Connect to the server and read a file containing the password for the next level.

I started by connecting to the server via SSH:

`ssh <username>@<host_IP> -p <port>`

After logging in, I used `ls` to locate the file in the home directory and `cat` to view its contents.

---

## Level 1 – Dash in Filename
**Goal**: Read a file with a dash (`-`) in its name.

The shell interprets a leading dash as an option. I could read the file using `./<filename>` or `-- <filename>`. The `--` tells the shell to stop interpreting anything after it as an option.

---

## Level 2 – Spaces in Filename
**Goal**: Read a file with spaces in its name.

Since spaces are interpreted as delimiters by the shell, I escaped them using backslash: `read\ the\ contents`. This can also be done by enclosing the filename within quotation marks.

---

## Level 3 – Hidden File Discovery
**Goal**: Find a hidden file.

Hidden files in Linux begin with a dot (`.`). I used the `-a` option with `ls` to list all files, including hidden ones, and used `cat` to read the file contents.

This step reinforced the knowledge I gained from Google cybersecurity coursework.

---

## Level 4 – Identify Text in Binary Files
**Goal**: Find the only human-readable file in a directory with various file types.

The home directory had one folder with 10 files in it. Most files were binary. I used the `file` command to determine each file's type. As all the files in the folder had a dashed filename, I used `file -- *`. `file *` does not look through files starting with `-` as it will consider them to be options and not filenames. `file ./*` or `file -- *` will work. 

Then I filtered with `grep 'text'` to locate "ASCII text" files. It revealed a file that had a dash in its name, so I accessed it using `-- <filename>`. 

There was only one file in this case that was a text file, so piping `file` and `grep` with `cut -d: -f1 | xargs cat` would directly display the output. The `-d` delimiter uses `:` as the actual delimiter, `-f1` means field one (the first part of the output before `:`).

Alternatively using `strings ./*` would retrieve all human-readable strings within the files, and would be a simpler solution. 

---

## Level 5 – Find File by Size and Permissions
**Goal**: Find a file with specific properties (human-readable, 1033 bytes, non-executable).

I initially used the `find` command with the `-size` option. There was only one match, so it was straightforward. I confirmed it wasn't executable by using `ls -l`.

However, a more accurate method for future levels would be to use `find` with `-size`, `! -perm`, `-exec file {} +`, filtering with `grep 'text'`. 

<details>
<summary><strong>Spoiler: More Accurate Approach</strong></summary>
`find . -size <size_c> ! -perm -111 -exec file {} + | grep 'text'`
</details>

---

## Level 6 – Locate File by Owner and Group
**Goal**: Locate a file located somewhere on the server, owned by a specific user, bandit7 and group, bandit6 with a specific file size 33 bytes.

I searched the root directory (`/`) using `find` with `-user`, `-group`, and `-size` filters. Since I searched the root directory, this displayed many files and most of which gave a "Permission denied" error. I then redirected standard permission errors, i.e., file descriptor 2 (`2>`), to `/dev/null` which is a special file that discards all data written to it. It then displayed one file which contained the password.

**File descriptors**: `0` for stdin, `1` for stdout, `2` for stderr. The `2>` tells the shell to redirect file descriptor 2 (stderr) to `/dev/null`.

---

## Level 7 – Grep for Keyword
**Goal**: Find the password next to the word "millionth" in a file.

I used `grep` to search for the word "millionth" in the file, which revealed the password.

---

## Level 8  – Find Unique Line
**Goal**: Find the only line in a file that occurs only once.

I used a combination of `sort` and `uniq` (also similar to `sort -u`) to filter repeated lines. However, this revealed several lines. So, I had to repeat with `uniq` option `-u` to isolate the unique line. 

---

## Level 9 – Strings from Binary
**Goal**: Extract a human-readable string, preceded by several '=' characters, from a binary file.

I initially used `grep`, which returned a "binary file matches" message. This means `grep` found a match but does not print it as it assumes binaries are not meant to be printed. So, I used the `strings` command to extract readable content, then piped it to `grep` to reveal the password.

---

## Level 10 – Base64 Decoding
**Goal**: Decode a base64-encoded file.

I used `base64` command with option `-d` to decode the password.

---

## Level 11 – ROT13 Decryption
**Goal**: Decode a ROT13 (Caesar cipher) encoded message.

As 'A-Z' and 'a-z' were rotated 13 positions, i.e., A is N and Z is M. I used the `cat` command to pipe input into `tr` command to decode the message.

Although the ROT13 cipher is a basic cipher, it served as an introduction to simple **cryptography**.

<details>
<summary><strong>Spoiler: Reveal Answer</strong></summary>
tr 'A-Za-z' 'N-ZA-Mn-za-m'
</details>

---

## Level 12 – Unpack Multi-layered Archive
**Goal**: The password for the next level is stored in a file that has been repeatedly compressed and is represented as a **hexdump**. The challenge involves extracting and decompressing the file to reveal the password.

I started by creating a temporary directory using `mktemp -d` and copied the `data.txt` file there. The file was a hexdump, which began with the signature `1F 8B` for `Gzip (GNU zip)` and also had ASCII string `BZh` (magic number `42 5a 68`), indicating `Bzip2` compression inside gzip.

Using `xxd -r`, I reverted it back into its binary form. The binary file was compressed multiple times using different formats, including **gzip**, **bzip2**, and **tar**.

I used the `file` command at each step to identify the compression format. After extracting the first layer, it revealed another compressed file, which required a different decompression method. This process was repeated multiple times until I reached a human-readable file containing the password.

I ran into an issue where `gunzip` or `gzip -d` didn't recognize some files as gzip-compressed unless they had a `.gz` extension. Since the files didn't have this extension, I renamed them each time to allow `gunzip` to detect and decompress them properly. This happens because `gunzip` relies on the `.gz` extension to identify gzip files.

To extract file from `tar` archive I used `tar` command with `-xf` flag to specify extract & specify the file to be extracted.

This level further sharpened my understanding of working with compressed files and Linux utilities.

---
## Level 13  – SSH with Private Key
**Goal**: Retrieve the password for the next level using SSH key authentication instead of password authentication.

This level introduced **SSH key-based authentication**. Instead of receiving a password, I found a private SSH key that granted access to the next level. I used the `-i` (identity file) option with SSH to specify the private key file for authentication. Once connected, I located the password file that could only be accessed by the target user `bandit14`.

`ssh -i <privatekey_file> <username>@<hostname> -p <port>`

This level reinforced the concept of **public-key cryptography** and how SSH keys provide secure, password-free authentication.

---

## Level 14 – Send Password via Netcat
**Goal**: Submit the current level's password to a specific port on localhost to retrieve the next password.

I used netcat (`nc`) to establish a **TCP connection** to the specified port on localhost and transmitted the password:

`echo "<password>" | nc <hostname> <port>`

This level introduced basic network communication and how services can listen on specific ports for data transmission.

---

## Level 15 – Send Password via SSL
**Goal**: Submit the current level's password using SSL/TLS encryption to retrieve the next password.

This challenge required establishing an **encrypted connection** using SSL/TLS. I used the `openssl s_client` command along with `-connect <hostname>:<port>` to create a secure connection to the specified port.

This level introduced how to use `openssl s_client` to connect to services over SSL/TLS-encrypted channels.

---

## Level 16 – Port Scan & SSL Key Retrieval
**Goal**: Find the correct SSL/TLS enabled port within a specified range and submit the password to retrieve SSH credentials for the next level.

This level combined multiple concepts: **port scanning**, **service identification**, and **SSL/TLS communication**. I used `ss` (socket statistics) to identify listening ports within the specified range:

`ss -tln '( sport >= <start_port> and sport <= <end_port> )'`

The options `-tln` specify: show only TCP sockets, listening sockets, and don't resolve host/service names (show ports/IPs numerically). The syntax uses `sport` (source port) with comparison operators (`=`, `!=`, `<`, `<=`, `>`, `>=`) combined with boolean operators (`and`, `or`, `!`) to filter ports within the range, demonstrating command-line filtering.

After identifying active ports, I tested each to determine which ones supported SSL/TLS encryption using:

`openssl s_client -connect <hostname>:<port> -quiet`

After the TLS handshake completed, I entered an interactive session with the server where I could send the password and receive responses. The `-quiet` flag was essential as it suppresses verbose connection information and diagnostic output (as documented in the `openssl s_client` man page under connected commands) - without it, the server's response would be cluttered with connection details, making it difficult to extract sensitive info like a private key.

The correct port returned an **RSA private key**. I saved this key to a temporary file and used it for SSH key authentication to access the next level. This challenge highlighted the importance of reconnaissance in cybersecurity.

---

## Level 17 – Compare Files for Difference
**Goal**: Find the password by comparing two files and identifying the line that differs between them.

This level focused on **file comparison** and **data analysis**. I used `sort <file1> <file2>` to sort both files, piped it to `uniq -u` to find lines that appeared only once. This revealed two unique lines. Then I matched the differing line using `grep` to determine which unique line belonged to the target file.

The challenge reinforced skills in text processing and pattern matching, essential for log analysis and forensic investigations in cybersecurity.

---

## Level 18 – Bypass Restricted Shell
**Goal**: Retrieve the password from a file while bypassing a modified shell configuration that prevents normal login.

This challenge demonstrated **shell bypass techniques**. The `.bashrc` file contained exit commands, which caused the shell to immediately close upon login, preventing normal interactive sessions. Investigation revealed the file contained `exit 0` commands that forced logout upon login. I bypassed the restricted shell by running SSH command along with `cat` command to retrieve the file contents without entering an interactive shell. 

`ssh username@host -p <port> "cat <file_path>"`

Note: Although using the ssh `-t` flag wasn't necessary for this level, this flag forces allocation of a pseudo-terminal, which tricks the server into treating the session as interactive — useful when the shell tries to auto-logout.

This showcased how attackers might bypass security restrictions. The level emphasized the importance of understanding **shell behavior** and **remote command execution** in both offensive and defensive security contexts.

---

## Level 19 – Setuid Binary to Read Password
**Goal**: To gain access to the next level, you should use the setuid binary in the homedirectory. Execute it without arguments to find out how to use it.

This level has an executable file in the home directory. The owner's execute bit (`x`) is replaced by `s`, which means the setuid bit is set — the program will run with the owner's privileges (`bandit20`). Since the group `bandit19` has execute permission (`r-x`), any user who belongs to group `bandit19` can execute the file, and it will run as `bandit20`. I used this file to view the password of the next level.

---

## Level 20 – Netcat + Setuid Binary Communication
**Goal**: There is a setuid binary in the homedirectory that does the following: it makes a connection to localhost on the port you specify as a commandline argument. It then reads a line of text from the connection and compares it to the password in the previous level (bandit20). If the password is correct, it will transmit the password for the next level (bandit21).

I initially misunderstood what the setuid file does. I thought it sends the password of the next level within the same terminal, where what it does is read the password sent to it and sends the password over to the terminal or port that connected to it. 

I first set up a listener using `nc -ln <port>` in one terminal (through an unused port) and then executed the binary in another with the port number as the argument.

The binary file read the password of this level and sent me the next password to the first terminal that connected to it.

---

## Level 21 – Read Password from Cron Job Output
**Goal**: A program is running automatically at regular intervals from cron, the time-based job scheduler. Look in /etc/cron.d/ for the configuration and see what command is being executed.

There was a cronjob run by bandit22 in `/etc/cron.d`. I looked at what it was running. `/usr/bin/cronjob_bandit22.sh  &> /dev/null` . The shellscript copied the password from /etc/bandit_pass to /tmp/<tempfile> and executed `chmod 644` on the same temp file. So I simply read that file using `cat`.

---

## Level 22 – Predict Cron Job Output Path
**Goal**: A program is running automatically at regular intervals from cron, the time-based job scheduler. Look in /etc/cron.d/ for the configuration and see what command is being executed.

There was a cronjob run by bandit23 in /etc/cron.d. I looked at what it was running. `/usr/bin/cronjob_bandit23.sh  &> /dev/null` . It was running a shellscript which was:
myname=$(whoami)
mytarget=$(echo <xyz> | md5sum | cut -d ' ' -f 1)
echo "Copying passwordfile /etc/bandit_pass/$myname to /tmp/$mytarget"
cat /etc/bandit_pass/$myname > /tmp/$mytarget

After analysing and understanding the script it was running, I first retrieved the md5 hash by using the same commands and echoing the same and then, viewed the temp file to retrieve the password.

---

## Level 23 – Exploit Cron Job to Execute Script
**Goal**: A program is running automatically at regular intervals from cron, the time-based job scheduler. Look in /etc/cron.d/ for the configuration and see what command is being executed.

There was a cronjob run by bandit24 in /etc/cron.d. I looked at what it was running. `/usr/bin/cronjob_bandit24.sh  &> /dev/null` . It was running a shellscript which was executing and removing all files in `/var/spool` that belonged to bandit23. 

cd /var/spool/$myname/foo
echo "Executing and deleting all scripts in /var/spool/$myname/foo:"
for i in * .*;
do
    if [ "$i" != "." -a "$i" != ".." ];
    then
        echo "Handling $i"
        owner="$(stat --format "%U" ./$i)"
        if [ "${owner}" = "bandit23" ]; then
            timeout -s 9 60 ./$i
        fi
        rm -f ./$i
    fi
done

This was the loophole I used to run a file that reads the next level password and write to a temp file that I can access. This was the first shellscript I wrote.
So I created a shell script that read `/etc/bandit_pass/bandit24` and wrote its contents to `/tmp/<tempdir>`. I changed the execute value and copied it to `var/spool` so bandit24 cronjob can execute it. 
I first tried to write it to a temp directory I created, but this did not work as it probably did not have permissions to write into a temp directory I created. I then made it write directly to the temp directory, specifying a filename so I can view it.

---

## Level 24 – Brute-force Daemon with Bash
**Goal**: A daemon is listening on port 30002 and will give you the password for bandit25 if given the password for bandit24 and a secret numeric 4-digit pincode. There is no way to retrieve the pincode except by going through all of the 10000 combinations, called brute-forcing.

Mistakes and learnings included:
- Without any knowledge of Bash scripting, I initially tried to use `for i in range`, when I should have used `seq` instead.
- I initially tried saving the sequence in a variable as `list="$(seq 0000 00001 9999)"`, but later decided to use the sequence directly to keep the script simple. I also learned that there should be no space before or after the `=` sign when assigning a variable in Bash.
- To generate 4-digit numbers, I originally used a step value: `seq 0000 00001 9999`, but later learned that `seq -w 0000 9999` is the better approach, as the `-w` flag preserves width and leading zeroes.
- I mistakenly used `EOF` (unquoted) when creating the script with a heredoc. This caused variable expansion at script creation time — `for i in $(seq -w 0000 9999)` was expanded into `for i in 0000 0001 ... 9999`. Quoting `'EOF'` is important to preserve the contents so they are evaluated only when the script is executed, not when it's written.
- I initially used `nc` without a timeout:
`response=$(echo "gb8KRRCsshuZXI0tUuR6ypOFjiZbf3G8 $i" | nc localhost 30002)` — but this caused the loop to hang at `0000`.
- To test the input format before running the full script, I manually ran: `echo <password> <PIN> | nc localhost 30002`. This helped verify that the input format was correct and that the service responded as expected.
- Enabling debug mode with `set -x` after the shebang (`#!/bin/bash`) helped me trace command execution. 
- I experimented with different timeout durations. A large timeout like `1` second caused the connection to stay open too long, slowing down brute-force attempts and eventually closing the SSH session. On the other hand, a very short timeout like `0.01` was too aggressive and resulted in incorrect responses.
- `timeout 1 nc localhost 30002` is not the same as `nc -w 1 localhost 30002`. `timeout` forcefully kills the entire command after 1 second, while `nc -w` tells `netcat` to wait 1 second for I/O before exiting. They behave differently. Although I did not combine them, they can be used together if needed.
- I used a conditional `if` statement to print responses only every few tries to provide a sense of progress. To avoid cluttering the terminal, I only printed responses every 1000 attempts: `if (( 10#$i % 1000 == 0 )); then ...`. This provided a sense of script progress without flooding the output.
-  Bash treats numbers with leading zeros as octal (base-8), so forcing base-10 (`10#$i` base 10 interpretation) avoids syntax errors. Without `10#`, if `$i` starts with a zero, Bash may interpret it as octal (base-8) and causes errors for values >7 (e.g., 08, 09 are invalid in octal).
- Finally, I learned the difference between [[ ... ]] and (( ... )):
[[ ... ]] is the Extended Test Command, used for string comparison, pattern matching, and logical expressions. (( ... )) is used for arithmetic evaluation.

This level taught me not only how to interact with services using Bash, but also how to build scripts by understanding heredocs, quoting rules, arithmetic evaluation, and network timeouts. 

---

## Level 25 – Escaping Restricted Pager Shell
**Goal**: Logging in to bandit26 from bandit25 should be fairly easy… The shell for user bandit26 is not /bin/bash, but something else. Find out what it is, how it works and how to break out of it.

Mistakes and learnings included:

- I learned that `/etc/passwd` contains the login shell for each user, and I used `grep` to help extract it. This revealed that bandit26's shell is not `/bin/bash`, but a restricted script, `/usr/bin/showtext`.
- I used cat command to reveal the contents of the file `/usr/bin/showtext`. This revealed that the script executes `more ~/text.txt`.
- I mistakenly assumed that `text.txt` was important to the challenge itself. In reality, the `more` command was the core restriction mechanism, not the file content.
- I tried editing `/usr/bin/showtext` using `vim` with custom commands like `+cat` and `+echo`, not realizing I lacked write permissions and that editing this file was irrelevant to the solution.
- Although I realized early on that using the provided private key from the home directory would log me in, I didn't understand how `more` behaved or how to interact with it.
When logging in, I didn't initially recognize that I was inside `more` because it simply printed the file contents and then terminated the connection with `exit 0`.
- Only after resizing my terminal window (to something small) and logging in again did I notice the pager behavior of `more` (the `--More--` prompt), which confirmed I was in a restricted shell running `more ~/text.txt`.
- Not knowing how to proceed, I began pressing `v`, which opened the file in `vi`. But I only tried running: `:!bandit27-do`, an executable file in level 26 home directory. 
This failed, as expected, since `bandit26` doesn't have permission to execute `bandit27-do` directly that way.
- Eventually, I discovered the actual escape:
Once inside `more`, I pressed `v` to open `text.txt` in `vi`. Pressing `v` again switched to visual mode, and another `v` allowed me to enter command mode. From there I pressed `:` to enter command mode and set a shell, followed by `:shell` to escaped into a real shell. This successfully dropped me into an interactive shell as `bandit26`, allowing me to access the next level's files.

Key Takeaways:
- You cannot bypass `showtext` directly — it always runs `more ~/text.txt`.
- `more` is vulnerable to terminal misbehavior — resizing, key spamming (pressing `v` multiple times), and entering `vi` or visual mode.
- Once in `vi`, set a shell using `:set shell=/bin/bash`, then use `:shell` to escape into an interactive shell.

---

## Level 26 – Use Setuid to Read Password
**Goal**: Hurry and grab the password for bandit27!

This level has an executable file that let me execute a command as bandit27. So I simply used cat command to view the password for the next level.
This worked because the binary is setuid and allows execution of a command as bandit27.

---

## Level 27 – Basic Git Clone & Retrieve
**Goal**: There is a git repository at `ssh://bandit27-git@localhost/home/bandit27-git/repo` via the port `2220`. The password for the `user bandit27-git` is the same as for the user `bandit27`. Clone the repository and find the password for the next level.

Challenges faced:
- Snippet from `man git`:

> git-clone(1): Clone a repository into a new directory.

When I tried `git-clone`, I received the error: `command not found: git-clone`. This is probably because `git-clone` is a low-level executable used internally by Git, not meant to be run directly. Instead, `git clone` is the correct high-level command to use for cloning repositories.

- I created a temporary directory inside `/tmp` using `mktemp -d` and cloned the repository there. This repository contained a file called `README`, which had the password.
- I then made another mistake: I forgot to specify the port when cloning.
Git requires specifying a non-default SSH port using the -p option or by modifying the URL like this:
`git clone ssh://username@hostname:2220/home/repo`

---

## Level 28 – Explore Git History for Secrets
**Goal**: There is a git repository at ssh://bandit28-git@localhost/home/bandit28-git/repo via the port 2220. The password for the user bandit28-git is the same as for the user bandit28. Clone the repository and find the password for the next level.

I used `git clone` to clone repository and read its contents. The password was hidden. I used `git log` to check for previous commits and checked out the previous commits using `git checkout` and used `git show` to reveal previous commits. I later realised `git checkout` was not necessary for this level.
`git show 123456a00a0011ab...` = `git show 123456a`
Git allows the use of abbreviated hashes such as `12345a`. `--oneline` usually show these for readability. `--oneline` shows each commit in online and more compact than the default `git log`, which shows full author, date, etc.

/tmp is world-writable and shared across users. I initially tried to clone the repository directly into /tmp directory and this gave me an error "fatal: destination path 'repo' already exists". I found many directories called repo, repo2, repo3 etc. These found files were likely left behind by other players. It was not part of the intended challenge path. Although unrelated to this level, I viewed some repos that existed within the `/tmp` and found the password for level 30, and also repos related to other levels (however did not contain any passwords). 

---

## Level 29 – Branch Discovery
**Goal**: There is a git repository at ssh://bandit29-git@localhost/home/bandit29-git/repo via the port 2220. The password for the user bandit29-git is the same as for the user bandit29.

After cloning the repository, I viewed the contents. It did not contain the password as I thought. I tried all commits displayed by `git log` and none of them had the password. I then used `git branch -a` to show all branches, used `git checkout` to move to a particular branch and then `git show` to reveal the commit changes and hence the password.

I also learnt that alternatively I could have used `git log --all --graph --oneline` to show all branch commits and one commit per line, and then use git show to reveal password. `--graph` adds a text-based graph showing the commit structure (branches, merges).

---

## Level 30 – Finding Tagged Commit
**Goal**: There is a git repository at ssh://bandit30-git@localhost/home/bandit30-git/repo via the port 2220. The password for the user bandit30-git is the same as for the user bandit30. Clone the repository and find the password for the next level.

`git log` had one commit. `git branch` with only one branch (master). I used `git tag` to show tags and this revealed the password. 

There are two types of tags in Git:
- Lightweight tag: Like a bookmark — just a name pointing to a commit.
- Annotated tag: Stores additional metadata like the tagger's name, email, date, and a message (and is stored as a full object in Git).

`git tag` points to a commit, but this commit was not shown in `git log`. This is because this commit was removed from the history of git, which removes its commit from `git log`. If the commit hash is known, this could still be accessed, as a commit cannot be deleted on git.

A commit pointed to by a tag may not show in git log if it's not on any branch. It's still reachable by the tag reference.

---

## Level 31  – Git Push with Hook Rejection
**Goal**: There is a git repository at ssh://bandit31-git@localhost/home/bandit31-git/repo via the port 2220. The password for the user bandit31-git is the same as for the user bandit31. Clone the repository and find the password for the next level.

This level required to push a file to the repository. As I have my in git, this was easier to solve. I used `git add`, `git commit -m` and `git push` to push the commit to the repository specified. Although this gave me the password, it also gave an error: "! [remote rejected] master -> master (pre-receive hook declined)
error: failed to push some refs to <repo>". 

The error was because of some restrictions. Some servers are configured with hooks to reject unauthorized pushes. Despite the rejection, the server-side script ran the commit to extract the password. I used `git log origin/master` to check if commit is local only. My new commit was not there, which means the push didn't go through.

I used `git log master ^origin/master` or `git log master --not origin/master` to compare local and remote branches. This showed commits in local master that the remote doesn’t have- my new commit.


## Level 32 – UPPERCASE Shell Escape
**Goal**: After all this git stuff, it's time for another escape. Good luck!

This logged into UPPERCASE SHELL, where everything I typed was interpreted as UPPERCASE. Typing `ls` becomes `LS`.
It took some research to figure out how to break this shell. I used Argument 0 (`$0`) which is a variable that holds the name of the currently running shell or script. So I used this to bypass typing `/bin/sh` directly in the UPPERCASE shell. 
I then simply used cat command to get the password to the next level.

---

## Key Learning Outcomes

### Technical Skills Developed
- **Linux System Administration**: File permissions, user management, process control
- **Network Security**: Port scanning, service identification, SSL/TLS communication
- **Cryptographic Operations**: Encoding/decoding, key management, secure communications
- **Version Control Security**: Git repository analysis, commit history exploration, branch management
- **Shell Scripting**: Automation, error handling, network interaction
- **Binary Analysis**: File type identification, hexdump analysis, string extraction

### Security Concepts Understood
- **Privilege Escalation**: Setuid binaries, restricted shell bypasses, cron job exploitation
- **Reconnaissance**: Port scanning, service enumeration, information gathering
- **Access Control**: File permissions, user privileges, authentication mechanisms
- **Data Protection**: Encryption, secure transmission, key management
- **Attack Vectors**: Shell restrictions, service vulnerabilities, misconfigurations

### Problem-Solving Approach
- **Methodical Investigation**: Systematic approach to understanding each challenge
- **Tool Proficiency**: Effective use of command-line utilities and scripting
- **Error Handling**: Learning from failures and adapting strategies
- **Documentation**: Understanding man pages and technical documentation
- **Persistence**: Working through complex multi-step challenges

---

## Conclusion

This challenge improved my scripting, Git fluency, and ability to reverse-engineer unusual constraints (e.g. restricted shells, cron jobs, Git internals). I also developed a better understanding of network services, command-line utilities, and Linux privilege escalation.

The progression from basic file operations to complex privilege escalation techniques demonstrates a comprehensive understanding of Linux security concepts and practical cybersecurity skills. Each level built upon previous knowledge while introducing new challenges that required creative problem-solving and technical expertise.

---