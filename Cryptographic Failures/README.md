<div align='center'>

# **Cryptographic Failures**

</div>

## **Table of Content**

- [**1. Description**](#1-description)
- [**2. How to test**](#2-how-to-test)
    - [**2.1. Test For Weak Transport Layer Security**](#21-test-for-weak-transport-layer-security)
    - [**2.2. Test For Padding Oracle**](#22-test-for-padding-oracle)
    - [**2.3. Test for Sensitive Information Sent via Unencrypted Channels**](#23-test-for-sensitive-information-sent-via-unencrypted-channels)
    - [**2.4. Test for Weak Encryption**](#24-test-for-weak-encryption)
- [**3. How to fix**](#3-how-to-fix)
- [**4. Tools**](#4-tools)
- [**5. References**](#5-references)

## **1. Description**

Cryptographic failures refer to any weaknesses or flaws in cryptographic systems that result in the protection they offer being compromised. This could be due to a number of factors such as design weaknesses, implementation errors, or attacks on the underlying cryptographic algorithms.

Cryptographic failures can have serious consequences, such as the compromise of sensitive information or the loss of trust in a system. It is important to continuously monitor and assess cryptographic systems to ensure that they are secure and free from failures.

For example, in this [Web Project](./Vuln%20Web/), in file [](./Vuln%20Web/html/classes/user.php), these two function is vulnerable to padding oracle attack:

```php
function encryptString($unencryptedText, $passphrase) { 
  $iv = mcrypt_create_iv( mcrypt_get_iv_size(MCRYPT_DES, MCRYPT_MODE_CBC), MCRYPT_RAND);
  $text = pkcs5_pad($unencryptedText,8);
  $enc = mcrypt_encrypt(MCRYPT_DES, $passphrase, $text, MCRYPT_MODE_CBC, $iv); 
  return base64_encode($iv.$enc); 
}

function decryptString($encryptedText, $passphrase) {
  $encrypted = base64_decode($encryptedText);
  $iv_size =  mcrypt_get_iv_size(MCRYPT_DES, MCRYPT_MODE_CBC);
  $iv = substr($encrypted,0,$iv_size);
  $dec = mcrypt_decrypt(MCRYPT_DES, $passphrase, substr($encrypted,$iv_size), MCRYPT_MODE_CBC, $iv);
  $str = pkcs5_unpad($dec); 
  if ($str === false) {
    echo "Invalid padding";
    die(); 
  }
  else {
    return $str; 
  }
}
```

Firstly, the encryption algorithm is DES, which is a weak encryption algorithm. Secondly, the encryption mode is CBC,  Finally, the padding error message is returned to the user. Both of these factors make the application vulnerable to padding oracle attack.

[Here](./Pentest%20Report.md) is how to exploit this vulnerability.

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
        - [ ] [TLS compression (CRIME)](https://en.wikipedia.org/wiki/CRIME)
        - [ ] [Weak DHE keys (LOGJAM)](https://weakdh.org/)
        - [ ] Weak Cryptographic Libraries


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

      Wildcard certificates can be convenient, however they violate the principal of least privilege, as a single certificate is valid for all subdomains of a domain (such as *.example.org). Where multiple systems are sharing a wildcard certificate, the likelihood that the private key for the certificate is compromised increases, as the key may be present on multiple systems. Additionally, the value of this key is significantly increased, making it a more attractive target for attackers.

      Here is the example of a wildcard certificate:

      ![](./img/7.png)

-   Application 

    - [ ] Use TLS For All Pages
    - [ ] Do Not Mix TLS and Non-TLS Content
    - [ ] Use the "Secure" Cookie Flag
    - [ ] Caching of Sensitive Data
    - [ ] Redirecting from HTTP to HTTPS
    - [ ] Not sending sensitive data over unencrypted channels
    
### **2.2 Test For Padding Oracle**

- [ ] Find encrypted data in the application
- [ ] A block cipher is used to encrypt the data. The length of the data is a multiple of the common cipher block size like 8 or 16 bytes.
- [ ] The application uses CBC mode to encrypt the data.
- [ ] The application uses PKCS#5 or PKCS#7 padding.
- [ ] The application returns the padding error message to the user.

### **2.3 Test for Sensitive Information Sent via Unencrypted Channels**

- [ ] The application sends sensitive information using HTTP instead of HTTPS.
- [ ] Testing sensitive information in Source Code or Logs

### **2.4 Test for Weak Encryption**

- [ ] When using AES128 or AES256, the IV (Initialization Vector) must be random and unpredictable.
- [ ] For asymmetric encryption, use Elliptic Curve Cryptography (ECC) with a secure curve like `Curve25519` preferred.
    - [ ] If ECC can???t be used then use RSA encryption with a minimum 2048bit key
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
    - [ ] **Key exchange:** Diffie???Hellman key exchange with minimum 2048 bits 
    - [ ] **Message Integrity:** HMAC-SHA2
    - [ ] **Message Hash:** SHA2 256 bits
    - [ ] **Asymmetric encryption:** RSA 2048 bits
    - [ ] **Symmetric-key algorithm:** AES 128 bits
    - [ ] **Password Hashing:** PBKDF2, Scrypt, Bcrypt
    - [ ] **ECDH, ECDSA:** 256 bits
- [ ] Uses of SSH, CBC mode should not be used.
- [ ] When symmetric encryption algorithm is used, ECB (Electronic Code Book) mode should not be used.
- [ ] When PBKDF2 is used to hash password, the parameter of iteration is over 10000

## **3. How to fix**

-   Identify the type of cryptographic failure, such as weak encryption, key management issues, or poor randomness.
-   Use strong and up-to-date encryption algorithms, such as AES or RSA, that are suitable for your application's needs. With AES, do not use ECB or CBC mode.
-   Ensure that encryption keys are generated using secure and random sources, and are protected with proper key management mechanisms, such as key rotation and key revocation.
-   Use secure cryptographic protocols, such as TLS/SSLv3, to secure data in transit.
-   Use proper hashing algorithms, such as SHA-2, to securely store passwords and sensitive data. Do not use MD5 or SHA-1.
-   Avoid hard-coding cryptographic keys or secrets in your code or configuration files.
-   Use validated and secure cryptographic libraries and tools that are maintained and updated regularly.

The example from the previous section can be fixed like below.

```php
function encryptString($unencryptedText, $passphrase) { 
  $iv = mcrypt_create_iv( mcrypt_get_iv_size(MCRYPT_DES, MCRYPT_MODE_CFB), MCRYPT_RAND);
  $text = pkcs5_pad($unencryptedText,8);
  $enc = mcrypt_encrypt(MCRYPT_DES, $passphrase, $text, MCRYPT_MODE_CFB, $iv); 
  return base64_encode($iv.$enc); 
}

function decryptString($encryptedText, $passphrase) {
  $encrypted = base64_decode($encryptedText);
  $iv_size =  mcrypt_get_iv_size(MCRYPT_DES, MCRYPT_MODE_CFB);
  $iv = substr($encrypted,0,$iv_size);
  $dec = mcrypt_decrypt(MCRYPT_DES, $passphrase, substr($encrypted,$iv_size), MCRYPT_MODE_CFB, $iv);
  $str = pkcs5_unpad($dec); 
  if ($str === false) {
    echo "Something went wrong";
    die(); 
  }
  else if ($strpos($str, "user=") !== 0){
    echo "Something went wrong";
    die();
  }
  else {
    return $str; 
  }
}
```

## **4. Tools**

- [Burp Suite](https://portswigger.net/)
- [Nmap](https://nmap.org/)
- [WireShark](https://www.wireshark.org/)
- [TCPDUMP](https://www.tcpdump.org/)

**SSL Analyze**
- [sslscan](https://github.com/rbsec/sslscan)

  Example Usage: [here](./doc/sslscan.txt)

- [sslyze](https://github.com/nabla-c0d3/sslyze)

  Example Usage: [here](./doc/sslyze.txt)

- [SSL Labs](https://www.ssllabs.com/ssltest/)

  Example Result: https://www.ssllabs.com/ssltest/analyze.html?d=cmctelecom.vn

**Padding Oracle Attack**

- [PadBuster](https://github.com/GDSSecurity/PadBuster)

  Usage: padbuster.pl URL EncryptedSample BlockSize [options]
  
  Result: [here](./doc/padbuster.txt)


## **5. References**

- https://owasp.org/Top10/A02_2021-Cryptographic_Failures/
- https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/README
- https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html
