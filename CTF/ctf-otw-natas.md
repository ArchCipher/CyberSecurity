# <p align="center"> CTF Challenge: Web Security Fundamentals (OverTheWire: Natas) </p>

**Platform:** OverTheWire  
**Objective:** Capture the flag/password to proceed to the next level through web application security testing

---

## Skills Demonstrated
- **Web Application Security**: Source code analysis, parameter manipulation, cookie tampering
- **Information Disclosure**: Directory traversal, file inclusion, source code exposure
- **Authentication Bypass**: Session manipulation, cookie forgery, access control circumvention
- **Input Validation**: Command injection, path traversal, parameter pollution
- **Cryptographic Analysis**: XOR encryption, encoding/decoding, key derivation
- **HTTP Protocol**: Header manipulation, referrer spoofing, request interception

## Tools Used
- **Web Browsers**: Developer tools, source code inspection, network monitoring
- **Interception Tools**: Burp Suite, browser developer tools, request modification
- **Command Line**: Base64 encoding/decoding, hex manipulation, text processing
- **Programming**: Python scripting for cryptographic operations, HTTP requests

---

## Overview
The **Natas Wargames** are a series of web security challenges designed to teach fundamental web application security concepts. Each level introduces new vulnerabilities involving **information disclosure**, **authentication bypass**, **input validation**, and **cryptographic weaknesses**.

I have completed **Level 12**. Levels 0-12 presented challenges involving **source code analysis**, **HTTP header manipulation**, **command injection**, **XOR encryption**, and **file upload vulnerabilities**, requiring understanding of web protocols, cryptographic concepts, and web application security testing techniques.

Below is a walkthrough of the challenges I've completed, along with the techniques I used.

---

## Level 0 - Source Code Disclosure
**Hint Given**: "You can find the password for the next level on this page."

I started by accessing the provided URL and examining the page source code using browser developer tools (right-click → View Page Source or Ctrl+U). The password was embedded as an HTML comment within the page source.

This level introduced the concept of **information disclosure** through source code comments, a common web application vulnerability.

---

## Level 1 - Disabled Right-Click Bypass
**Hint Given**: "You can find the password for the next level on this page, but rightclicking has been blocked!"

The page had JavaScript that prevented right-click context menu access. I bypassed this restriction by using keyboard shortcuts (Ctrl+U or Cmd+Option+I) to access the page source directly.

This demonstrated how client-side restrictions can be easily bypassed and the importance of server-side security controls.

---

## Level 2 - Directory Traversal and File Discovery
**Hint Given**: "There is nothing on this page." + `<img src="files/pixel.png">` in source code

I examined the page source and discovered references to a `/files/` directory. By navigating to this directory, I found accessible files including a `users.txt` file containing credentials. This level also taught me that `/index-source.html` can be used to view source code for Natas websites.

---

## Level 3 - Robots.txt and Hidden Directories
**Hint Given**: "There is nothing on this page." + `<!-- No more information leaks!! Not even Google will find it this time... -->` in source code

I accessed the `/robots.txt` file which revealed a disallowed directory `/s3cr3t/`. By navigating to this directory, I found additional files containing the password. I had to research what robots.txt does and learned it controls web crawler access.

---

## Level 4 - HTTP Referrer Header Manipulation
**Hint Given**: "Access disallowed. You are visiting from "" while authorized users should come only from "http://natas5.natas.labs.overthewire.org/""

The application checked the `Referer` header to ensure requests came from a specific authorized domain. I intercepted the request using browser developer tools or Burp Suite and modified the `Referer` header to match the expected value. Initially, I tried changing multiple parameters before identifying the correct one to modify.

---

## Level 5 - Cookie Manipulation
**Hint Given**: "Access disallowed. You are not logged in"

The application used a `loggedin` cookie to track authentication status. I intercepted the request and changed the cookie value from `0` to `1` to bypass the authentication check.

---

## Level 6 - Source Code Analysis and File Inclusion
**Hint Given**: "Input secret:"

I accessed the source code through the `index-source.html` endpoint and discovered that the application included a `secret.inc` file. By directly accessing this include file, I found the secret value needed to pass the authentication check.

---

## Level 7 - Local File Inclusion (LFI)
**Hint Given**: Navigation links to "home" and "about" pages + `<!-- hint: password for webuser natas8 is in /etc/natas_webpass/natas8 -->` in source code

The application used a `page` parameter to include different content. I discovered that this parameter was vulnerable to **Local File Inclusion (LFI)** by changing the parameter value to read system files like `/etc/natas_webpass/natas8`.

---

## Level 8 - Reverse Engineering Encoding Functions
**Hint Given**: "Input secret:"

The application used a custom encoding function that combined base64 encoding, string reversal, and hexadecimal conversion. I analyzed the function and created a reverse process using command-line tools:

```bash
echo <encoded_value> | xxd -r -p | rev | base64 -d
```

---

## Level 9 - Command Injection
**Hint Given**: "Find words containing:"

The application used the `passthru()` function to execute system commands with user input. I exploited this by injecting command separators (`;`) to execute additional commands that read the password file. Having experience with SQL injection from PortSwigger labs, I recognized this as injection but had to learn that `;` is used to separate commands in shell environments, unlike SQL injection where `'` is used.

---

## Level 10 - Command Injection with Filter Bypass
**Hint Given**: "For security reasons, we now filter on certain characters. Find words containing:"

The application implemented basic filtering for command separators (`;`, `|`, `&`). I bypassed this by using newline characters (`\n`) to separate commands, which were not filtered.

---

## Level 11 - XOR Encryption Analysis and Cookie Forgery
**Hint Given**: "Cookies are protected with XOR encryption" and background color selector

The application used XOR encryption to protect cookie data. I had never worked on cryptography challenges with key, cipher, and plaintext before. I analyzed the encryption function and derived the encryption key through cryptographic analysis:

1. **Base64 decoding** the existing cookie
2. **XOR decrypting** with known plaintext to derive the key
3. **XOR encrypting** modified plaintext with the derived key
4. **Base64 encoding** the result to create a forged cookie

**Challenges and Learnings:**
- Learned that when cipher and plaintext are available, the key can be obtained
- Discovered XOR encryption and its properties
- Used Python to derive the XOR key:
```py
import base64
cipher = base64.b64decode("original_cookie")
plaintext = b'{"showpassword":"no","bgcolor":"#ffffff"}'
key = xor_encrypt(cipher, plaintext)
```
- Constructed new plaintext and encrypted it back to create the cookie:
```py
modified_plaintext = b'{"showpassword":"yes","bgcolor":"#ffffff"}'
key = key[:len(set(key))] # sanity filter (trim derived key to just the repeating part)
cipher2 = xor_encrypt(modified_plaintext, key)  # XOR encrypt the modified plaintext
new_cookie = base64.b64encode(cipher2).decode()
```
- **Critical Mistake:** Initially didn't use sanity filter `key = key[:len(set(key))]` to trim the derived key to just the repeating part
- The wrong cookie didn't work, causing confusion about where the error was
- Used Python requests to forward the new cookie and retrieve the password

This level introduced **cryptographic vulnerabilities** and demonstrated how weak encryption schemes can be reverse-engineered.

---

## Level 12 - File Upload Path Manipulation
**Hint Given**: File upload form with JPEG upload functionality (max 1KB)

**Status:** Not yet solved

---
