<div align='center'>

# **Cryptographic Failures**

</div>

## **1. Description**

Cryptographic failures refer to any weaknesses or flaws in cryptographic systems that result in the protection they offer being compromised. This could be due to a number of factors such as design weaknesses, implementation errors, or attacks on the underlying cryptographic algorithms.

Cryptographic failures can have serious consequences, such as the compromise of sensitive information or the loss of trust in a system. It is important to continuously monitor and assess cryptographic systems to ensure that they are secure and free from failures.

## **2. How to test**

### **2.1 Test For Weak Transport Layer Security**

-   Server Configuration 

    -   Weak Ciphers, Weak Protocols, Weak Keys

        - [ ] [SSLv2 (DROWN)](https://drownattack.com/)
        - [ ] [SSLv3 (POODLE)](https://en.wikipedia.org/wiki/POODLE)
        - [ ] [TLSv1.0 (BEAST)](https://www.acunetix.com/blog/web-security-zone/what-is-beast-attack/)
        - [ ] [TLSv1.1 (Deprecated by RFC 8996)](https://www.rfc-editor.org/rfc/rfc8996)
        - [ ] [EXPORT ciphers suites (FREAK)](https://en.wikipedia.org/wiki/FREAK)
        - [ ] [NULL ciphers](https://www.rapid7.com/db/vulnerabilities/ssl-null-ciphers/)
        - [ ] Anonymous ciphers 
        - [ ] [RC4 ciphers (NOMORE)](https://www.rc4nomore.com/)
        - [ ] CBC mode ciphers (BEAST, [Lucky 13](https://en.wikipedia.org/wiki/Lucky_Thirteen_attack))
        - [] [TLS compression (CRIME)](https://en.wikipedia.org/wiki/CRIME)
        - [] [Weak DHE keys (LOGJAM)](https://weakdh.org/)
        - [] Weak Cryptographic Libraries


-   Digital Certificates

    - [ ] Cryptographic Weaknesses

        - [ ] The key strength should be at least 2048 bits.
        - [ ] The signature algorithm should be at least SHA-256.

    - [ ] Test for Correct Domain Names

        - [ ] Have a Subject Alternate Name (SAN) that matches the hostname of the system.
        - [ ] Consider whether the "www" subdomain should also be included.
        - [ ] Do not include non-qualified hostnames.
        - [ ] Do not include IP addresses.
        - [ ] Do not include internal domain names on externally facing certificates

    - [ ] Test for the use of Wildcard Certificates

-   Application 

    - [ ] Use TLS For All Pages
    - [ ] Do Not Mix TLS and Non-TLS Content
    - [ ] Use the "Secure" Cookie Flag
    - [ ] Caching of Sensitive Data
    - [ ] Redirecting from HTTP to HTTPS
    - [ ] Not sending sensitive data over unencrypted channels

**Tools:**

- [ ] [Nmap](https://nmap.org/)
- [ ] [OWASP O-Saft](https://owasp.org/www-project-o-saft/)
- [ ] [sslscan](https://github.com/rbsec/sslscan)
- [ ] [sslyze](https://github.com/nabla-c0d3/sslyze)
- [ ] [SSL Labs](https://www.ssllabs.com/ssltest/)
- [ ] [testssl.sh](https://github.com/drwetter/testssl.sh)
### **2.2 Test For Padding Oracle**

- [ ] Find encrypted data in the application
- [ ] A block cipher is used to encrypt the data. The length of the data is a multiple of the common cipher block size like 8 or 16 bytes.

**Tools**

- [ ] [Bletchley](https://code.blindspotsecurity.com/trac/bletchley)
- [ ] [PadBuster](https://github.com/GDSSecurity/PadBuster)
- [ ] [Padding Oracle Exploitation Tool (POET)](http://netifera.com/research/)
- [ ] [Poracle](https://github.com/iagox86/Poracle)
- [ ] [python-paddingoracle](https://github.com/mwielgoszewski/python-paddingoracle)

### **2.3 Test for Sensitive Information Sent via Unencrypted Channels**

- [ ] The application sends sensitive information using HTTP instead of HTTPS.
- [ ] Testing sensitive information in Source Code or Logs

**Tools**

- [ ] [curl](https://curl.haxx.se/)
- [ ] [grep](http://man7.org/linux/man-pages/man1/egrep.1.html)
- [ ] [WireShark](https://www.wireshark.org/)
- [ ] [TCPDUMP](https://www.tcpdump.org/)

### **2.4 Test for Weak Encryption**

- [ ] When using AES128 or AES256, the IV (Initialization Vector) must be random and unpredictable.
- [ ] For asymmetric encryption, use Elliptic Curve Cryptography (ECC) with a secure curve like `Curve25519` preferred.
    - [ ] If ECC can’t be used then use RSA encryption with a minimum 2048bit key
- [ ] When uses of RSA in signature, PSS padding is recommended.
- Weak hash/encryption algorithms:
    - [ ] MD5
    - [ ] RC4
    - [ ] DES
    - [ ] Blowfish
    - [ ] SHA1
    - [ ] 1024-bit RSA or DSA
    - [ ] 160-bit ECDSA
    - [ ] 80/112-bit 2TDEA (two-key triple DES)
- Minimum Key length requirements
    - [ ] **Key exchange:** Diffie–Hellman key exchange with minimum 2048 bits 
    - [ ] **Message Integrity:** HMAC-SHA2
    - [ ] **Message Hash:** SHA2 256 bits
    - [ ] **Asymmetric encryption:** RSA 2048 bits
    - [ ] **Symmetric-key algorithm:** AES 128 bits
    - [ ] **Password Hashing:** PBKDF2, Scrypt, Bcrypt
    - [ ] **ECDH, ECDSA:** 256 bits
- [ ] Uses of SSH, CBC mode should not be used.
- [ ] When symmetric encryption algorithm is used, ECB (Electronic Code Book) mode should not be used.
- [ ] When PBKDF2 is used to hash password, the parameter of iteration is over 10000

## **3. Lab**