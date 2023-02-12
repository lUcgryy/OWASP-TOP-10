<div align='center'>

# **Broken Access Control**

</div>

## 1. Description

Access control, sometimes called authorization, is how a web application grants access to content and functions to some users and not others. These checks are performed after authentication, and govern what 'authorized' users are allowed to do. Access control sounds like a simple problem but is insidiously difficult to implement correctly. A web application’s access control model is closely tied to the content and functions that the site provides. In addition, the users may fall into a number of groups or roles with different abilities or privileges.

Broken access control refers to a security vulnerability that occurs when an application does not properly restrict access to sensitive resources, such as user accounts, data, or functionality. This vulnerability can be exploited by attackers to gain unauthorized access to sensitive information, perform actions that should be restricted, or escalate their privileges to gain administrative access

There are some common broken access control vulnerabilities:

-   **Directory traversal**: This vulnerability occurs when an application allows a user to access files and directories that are outside the intended directory.
-   **Insecure direct object references (IDOR)**: This vulnerability occurs when an application uses predictable or sequential identifiers to access objects, such as user accounts, files, or database entries.
-   **Privilege escalation**: A user gets access to more resources or functionality than they are normally allowed, and such elevation or changes should have been prevented by the application
-   **Bypassing authorization schema**: Bypassing the restrictions and limitations set by an application's authorization mechanism, such as a user role or access level.

## **2. How to test**

### **2.1. Directory traversal**

- [ ] Identify the injection point on the URL
- [ ] Test for local file inclusion (LFI)
- [ ] Test for remote file inclusion (RFI)
- [ ] Test traversal on the URL parameters
- [ ] Test traversal on the cookie parameters

**Bypassing Technique**

- [ ] Absolute path
- [ ] Null byte
- [ ] URL encoding
- [ ] Double URL encoding
- [ ] Bypass `../` replace by "" non-recursively
- [ ] Bypass `../` with `;` (`..;/`)

**OS Specific**

- [ ] Unix
    -   Root directory: `/`
    -   Directory separator: `/`
- [ ] Windows
    -   Root directory: `<drive letter>:`
    -   Directory separator: `\` or `/`
- [ ] MacOS
    -   Root directory: `/`
    -   Directory separator: `/`

**Top 25 parameter that could be vulnerable to local file inclusion (LFI) vulnerabilities**

    ?cat={payload}
    ?dir={payload}
    ?action={payload}
    ?board={payload}
    ?date={payload}
    ?detail={payload}
    ?file={payload}
    ?download={payload}
    ?path={payload}
    ?folder={payload}
    ?prefix={payload}
    ?include={payload}
    ?page={payload}
    ?inc={payload}
    ?locate={payload}
    ?show={payload}
    ?doc={payload}
    ?site={payload}
    ?type={payload}
    ?view={payload}
    ?content={payload}
    ?document={payload}
    ?layout={payload}
    ?mod={payload}
    ?conf={payload}

**Vulnerbility functions**

- [ ] **php:** include(), include_once(), require(), require_once(), fopen(), readfile(), file_get_contents(), ...
- [ ] **JSP/Servlet:** java.io.File(), java.io.FileReader(), ...
- [ ] **asp:** include file, include virtual, ...

**Tools**

- [ ] [Dotdotpwn](https://github.com/wireghoul/dotdotpwn)
- [ ] [PathTraversal Fuzz String](https://github.com/xmendez/wfuzz/blob/master/wordlist/Injections/Traversal.txt)
- [ ] [OWASP Zap](https://www.zaproxy.org/)
- [ ] [Burp Suite](https://portswigger.net/)
- [ ] [DirBuster](https://sourceforge.net/projects/dirbuster/)
- [ ] grep
- [ ] Encoding/Decoding Tools

### **2.2. Authorization Schema Bypass**

- [ ] Testing for Horizontal Bypassing Authorization Schema

    - [ ] Is it possible to access resources that should be accessible to a user that holds a different identity with the same role or privilege?
    - [ ] Is it possible to operate functions on resources that should be accessible to a user that holds a different identity?

- [ ] Testing for Access to Administrative Functions

    - [ ] Identify the administrative functions
    - [ ] Is it possible to access administrative functions without being authenticated as an administrator?

- [ ] Testing for Access to Resources Assigned to a Different Role

    - [ ] Is it possible to access resources assigned to a different role?
    - [ ] Is it possible to retrive them, modify them, or delete them?

- [ ] Test override the target with custom headers

```
X-Original-URL
X-Rewrite-URL
X-Forwarded-For
X-Forward-For
X-Remote-IP
X-Originating-IP
X-Remote-Addr
X-Client-IP
```

**Tools**

- [ ] [OWASP Zap](https://www.zaproxy.org/)
- [ ] [Burp Suite](https://portswigger.net/)

### **2.3. Privilege Escalation**

- [ ] Testing for Role/Privilege Manipulation

    - [ ] Manipulation of User Group
    - [ ] Manipulation of User Profile
    - [ ] Manipulation of Condition Value
    - [ ] Manipulation of IP Address