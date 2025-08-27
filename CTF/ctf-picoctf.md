# picoCTF

--
At first i did not know what the flag looks like.
After some google search on what the flag looks like I could solve my first picoCTF challenge.

## DISKO 1
strings disko-1.dd | grep "picoCTF*"
---
## hashcrack
Access the server using `nc verbal-sleep.picoctf.net 53299`


1st was md5 hash `482c811da5d5b4bc6d497ffa98491e38` = password123
2nd was SHA-1 hash `b7a875fc1ea228b9061041b7cec4bd3c52ab3ce3` = letmein
2nd was SHA-256 hash`916e8c4f79b25028c9e467f1eb8eee6d6bbdff965f9928310ad30a8d88697745` = qwerty098
I used `https://hashes.com/en/decrypt/hash` to decrypt SHA-256 hash.

The flag is: picoCTF{UseStr0nG_h@shEs_&PaSswDs!_23622a7e}
---

## EVEN RSA CAN BE BROKEN???

`nc verbal-sleep.picoctf.net 51624`
Output:
N: 14284431289706078484915868531373104036880393730942432408580007916857650624358649232824695213221902708688755904295038113473849365238132830596000756599495666
e: 65537
cyphertext: 11820399685031646394938341203419245635775476581648319046078973048762282172917259426674645441454088455767348616787431091646091562190091053443730074280824887

> Note: e: 65537 is a Fermat prime, often used as the public exponent e in RSA

1. Calculate factors of N
```py
from sympy import factorint
factors = factorint(N)  # returns {p: 1, q: 1}
print(factors)
```
# Output:
{2: 1, 7142215644853039242457934265686552018440196865471216204290003958428825312179324616412347606610951354344377952147519056736924682619066415298000378299747833: 1}

2. Decrypt ciphertext to plaintext
```py
p=2
q= N // p # automatically generate the other large number 71422...
phi = (p - 1)*(q - 1)
d = pow(e, -1, phi)
P = pow(C, d, N)
print(P)
```
Output: 3030612722376619015339251852200174143198160267119207878925874759940477

Encryption code was:
```py
from sys import exit
from Crypto.Util.number import bytes_to_long, inverse
from setup import get_primes

e = 65537

def gen_key(k):
    """
    Generates RSA key with k bits
    """
    p,q = get_primes(k//2)
    N = p*q
    d = inverse(e, (p-1)*(q-1))

    return ((N,e), d)

def encrypt(pubkey, m):
    N,e = pubkey
    return pow(bytes_to_long(m.encode('utf-8')), e, N)

def main(flag):
    pubkey, _privkey = gen_key(1024)
    encrypted = encrypt(pubkey, flag) 
    return (pubkey[0], encrypted)

if __name__ == "__main__":
    flag = open('flag.txt', 'r').read()
    flag = flag.strip()
    N, cypher  = main(flag)
    print("N:", N)
    print("e:", e)
    print("cyphertext:", cypher)
    exit()
```
3. Decode the flag

`pow(bytes_to_long(m.encode('utf-8')), e, N)` means flag was a UTF-8 string and was encoded to bytes → then converted to a long integer (m). Then m^e mod N → the ciphertext

UTF-8 is a character encoding — a standard way to represent text as bytes (numbers) in computers. Text like "flag{test}" is human-readable, but RSA encryption works on numbers, not text.

Steps to encrypt a flag like "flag{test}":
- Text input: "flag{test}" → m
- UTF-8 encoding: .encode('utf-8') → b'flag{test}'
- Convert bytes to integer: bytes_to_long() → big integer
- RSA encryption: cipher = pow(m, e, N)

Convert text → bytes → number before encryption.

And for decryption: Decrypted integer → long_to_bytes(...) → b'flag{test}'
```py
pip install pycryptodome # if required
from Crypto.Util.number import long_to_bytes
P = 3030612722376619015339251852200174143198160267119207878925874759940477
flag = long_to_bytes(P).decode()
print("Flag:", flag)
```

---

## More on RSA

- Choose two prime numbers (p, q)
N = p*q
Example: p = 3, q = 11

Then,
N = p * q = 3 * 11 = 33, φ(N) = (p−1)(q−1) = 2 * 10 = 20

- Choose public exponent e
1 < e < φ(N)
e and φ(N) are coprime (GCD = 1)

3 and 30 are coprimes

ϕ(N)=(p−1)×(q−1) = 30
- Compute private exponent d
(e × d) mod φ(N) = 1
Example 3 × 7 = 21 → 21 mod 20 = 1

Public key = (e=3, N=33)
Private key = (d=7, N=33)

- Encrypt a plaintext message
C = (P^e) mod N
- Decrypt the ciphertext
P = (C^d) mod N

1. If P^e < N, then: C=P^e mod N=P^e (no modulo effect)⇒P= e root C
```py
import gmpy2
P = gmpy2.iroot(C, e)[0]
```
2. Small d (Private Exponent) — Wiener's Attack

There are tools for this:
RsaCtfTool
SageMath's wiener_attack() function

3. Factor N directly

If N is small (say < 100 bits), you can just factor it:
```py
from sympy import factorint
N = 9797
factors = factorint(N)  # returns {p: 1, q: 1}

phi = (p - 1)*(q - 1)
d = pow(e, -1, phi)
P = pow(C, d, N)
```
4. Common modulus attack

If two ciphertexts share the same modulus N, but different e values (say, e1, e2) for the same message, you can recover P.

This uses extended Euclidean algorithm to solve: 
C1​=Pe1modNC2​=Pe2modN⇒use ‘gcd(e1, e2)‘ trick