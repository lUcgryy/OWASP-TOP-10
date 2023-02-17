<div align='center'>

# **Insecure Design**

</div>

## **1. Description**

Insecure design is a vulnerability that occurs when the application is designed in a way that allows attackers to bypass the security controls. This vulnerability is not a bug, but a design flaw. It is usually caused by the lack of security requirements in the design phase.

Examples of Insecure Design vulnerabilities include:

-   Lack of proper input validation and sanitization mechanisms.
-   Absence of secure authentication and authorization mechanisms.
-   Poorly implemented or weak access control mechanisms.
-   Failure to protect sensitive data or use secure encryption algorithms.
-   Lack of secure coding practices or adherence to industry-standard security guidelines.

For example, in this [Web Project](./Vuln%20Web/), the developers accidentally allow HTTP protocols for the user to access the website.

```javascript
var server = http.createServer(app);
server.listen(3000, () => {
	console.log(`Server is running at port 3000`);
});

var secureServer = https.createServer(options, app);
secureServer.listen(3443, () => {
	console.log(`Server is running at port 3443`);
});
```

In this case, the user can access the website using HTTP protocol, which is not secure. The user's data can be intercepted by attackers using Wireshark.

![](./img/Checklist/1.png)

## **2. How to test**

- [ ] Test for Architecture
    - [ ] Is the software's architecture designed with security in mind?
    - [ ] Are there any design patterns or decisions that could introduce security risks?

- [ ] Test for Authentication and Authorization
    - [ ] Are authentication and authorization mechanisms properly implemented?
    - [ ] Are they strong and secure?
    - [ ] Are access control mechanisms properly implemented and effective?

- [ ] Test for Input Validation and Sanitization
    - [ ] Is input validation and sanitization properly implemented to prevent injection attacks such as SQL injection, command injection, or cross-site scripting?

- [ ] Test for Sensitive Data Exposure
    - [ ] Is sensitive data being properly protected and encrypted with strong algorithms?
    - [ ] Is there proper separation of duties for handling sensitive data?

- [ ] Test for Third-party Components
    - [ ] Are any third-party components used that have known security vulnerabilities?
    - [ ] Are these components being properly managed and updated?

- [ ] Test for Logging and Auditing
    - [ ] Are logging and auditing of security-related events sufficient and comprehensive?
    - [ ] Is there adequate monitoring and alerting in place for security events?

- [ ] Test for Secure Configuration
    - [ ] Are all security-related configuration settings properly set?
    - [ ] Are there any default or weak credentials or configurations that could be exploited?

- [ ] Test for Secure Development Practices
    - [ ] Is the development team following secure coding practices and adhering to industry-standard security guidelines and best practices?

## **3. How to fix**

-   Conduct a comprehensive security review of the system's design and architecture to identify potential security risks and vulnerabilities.
-   Implement secure design patterns and best practices to ensure that the software system is designed with security in mind.
-   Ensure that input validation and sanitization is properly implemented to prevent injection attacks such as SQL injection, command injection, or cross-site scripting.
-   Implement strong and secure authentication and authorization mechanisms to ensure that only authorized users can access the system.
-   Implement effective access control mechanisms to ensure that users are only able to access the resources that they are authorized to access.
-   Protect sensitive data by encrypting it with strong algorithms and implementing proper separation of duties for handling sensitive data.
-   Use secure coding practices and adhere to industry-standard security guidelines and best practices.
-   Monitor and audit the system's security-related events to ensure that any security incidents are detected and responded to promptly.

For above example, the developer removed the HTTP protocol or redirect the user to HTTPS protocol.

```javascript
app.all('*', (req, res, next) => {
	if (req.secure) {
		return next();
	}
	res.redirect('https://' + req.hostname + ':' + securePort + req.url);
});
```

## **4. Tools**

- [Burp Suite](https://portswigger.net/)
- [WireShark](https://www.wireshark.org/)
- [Nmap](https://nmap.org/)

## **5. References**

- https://owasp.org/Top10/A04_2021-Insecure_Design/
- https://crashtest-security.com/insecure-design-vulnerability/
- https://foresite.com/blog/owasp-top-10-insecure-design/