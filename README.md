<h2 align="center">Ecommerce Website Security CheckList</h2>

<p align="center">
  <em>List of considerations for commerce site auditing and security teams. This is summary of action points and areas that need to be built into the Techinical Specific Document, or will be checked in the Security testing phases..</em>
</p>

[![Join the chat at https://gitter.im/CodepinIO/Ecommerce-Website-Security-CheckList](https://badges.gitter.im/Front-End-Checklist/Lobby.svg)](https://gitter.im/CodepinIO/Ecommerce-Website-Security-CheckList)
[![CC0](https://img.shields.io/badge/license-CC0-green.svg)](https://creativecommons.org/publicdomain/zero/1.0/)

## SDLC and development guidelines
The OWASP Top 10 - 2013 includes the following changes as compared to the 2010 edition:

* [ ] Authentication controls (passwords, account lockouts, password resets, forgotten passwords, etc.)
* [ ] Authorisation controls (Access Restrictions)
* [ ] A2 Broken Authentication and Session Management (was formerly 2010-A3)

* [ ] Session Management 
    * [ ]  Session ID Properties: In order to keep the authenticated state and track the users progress within the web application, applications provide users with a session identifier (session ID or token) that is assigned at session creation time, and is shared and exchanged by the user and the web application for the duration of the session (it is sent on every HTTP request). The session ID is a “name=value” pair.
* [ ] Session ID Name Fingerprinting
    * [ ] The name used by the session ID should not be extremely descriptive nor offer unnecessary details about the purpose and meaning of the ID.
    * [ ] The session ID names used by the most common web application development frameworks can be easily fingerprinted [0], such as PHPSESSID (PHP), JSESSIONID (J2EE), CFID & CFTOKEN (ColdFusion), ASP.NET_SessionId (ASP .NET), etc. Therefore, the session ID name can disclose the technologies and programming languages used by the web application.
    * [ ] It is recommended to change the default session ID name of the web development framework to a generic name, such as “id”.
* [ ] Session ID Length: The session ID must be long enough to prevent brute force attacks, where an attacker can go through the whole range of ID values and verify the existence of valid sessions. 
    * [ ] The session ID length must be at least 128 bits (16 bytes).
    * [ ] Session ID Entropy: The session ID must be unpredictable (random enough) to prevent guessing attacks, where an attacker is able to guess or predict the ID of a valid session through statistical analysis techniques. For this purpose, a good PRNG (Pseudo Random Number Generator) must be used.
      The session ID value must provide at least 64 bits of entropy (if a good PRNG is used, this value is estimated to be half the length of the session ID).
Session ID Content (or Value): The session ID content (or value) must be meaningless to prevent information disclosure attacks, where an attacker is able to decode the contents of the ID and extract details of the user, the session, or the inner workings of the web application.
Session Management Implementation
Built-in Session Management Implementations:
The storage capabilities or repository used by the session management mechanism to temporarily save the session IDs must be secure, protecting the session IDs against local or remote accidental disclosure or unauthorized access.
Used vs. Accepted Session ID Exchange Mechanisms: A web application should make use of cookies for session ID exchange management. If a user submits a session ID through a different exchange mechanism, such as a URL parameter, the web application should avoid accepting it as part of a defensive strategy to stop session fixation.
Transport Layer Securityn order to protect the session ID exchange from active eavesdropping and passive disclosure in the network traffic, it is mandatory to use an encrypted HTTPS (SSL/TLS) connection for the entire web session, not only for the authentication process where the user credentials are exchanged.
The following set of HTTPS (SSL/TLS) best practices are focused on protecting the session ID (specifically when cookies are used) and helping with the integration of HTTPS within the web application:
Web applications should never switch a given session from HTTP to HTTPS, or viceversa, as this will disclose the session ID in the clear through the network.
Web applications should not mix encrypted and unencrypted contents (HTML pages, images, CSS, Javascript files, etc) on the same host (or even domain - see the “domain” cookie attribute), as the request of any web object over an unencrypted channel might disclose the session ID.
Web applications, in general, should not offer public unencrypted contents and private encrypted contents from the same host. It is recommended to instead use two different hosts, such as www.example.com over HTTP (unencrypted) for the public contents, and secure.example.com over HTTPS (encrypted) for the private and sensitive contents (where sessions exist). The former host only has port TCP/80 open, while the later only has port TCP/443 open.
Web applications should avoid the extremely common HTTP to HTTPS redirection on the home page (using a 30x HTTP response), as this single unprotected HTTP request/response exchange can be used by an attacker to gather (or fix) a valid session ID.
Web applications should make use of “HTTP Strict Transport Security (HSTS)” (previously called STS) to enforce HTTPS connections.
Input/Data validation (XSS, SQL injections, XML injections, client side and server side validations, etc)
Encryption (storage, transmission)
Application server hardening (IIS, Apache)
Use of CAPTCHA
Logging for user actions and protection of logs
A1 Injection
A3 Cross-Site Scripting (XSS) (was formerly 2010-A2)
A4 Insecure Direct Object References
A5 Security Misconfiguration (was formerly 2010-A6)
A6 Sensitive Data Exposure (2010-A7 Insecure Cryptographic Storage and 2010-A9 Insufficient Transport Layer Protection were merged to form 2013-A6)
A7 Missing Function Level Access Control (renamed/broadened from 2010-A8 Failure to Restrict URL Access)
A8 Cross-Site Request Forgery (CSRF) (was formerly 2010-A5)
A9 Using Components with Known Vulnerabilities (new but was part of 2010-A6 – Security Misconfiguration)
A10 Unvalidated Redirects and Forwards
