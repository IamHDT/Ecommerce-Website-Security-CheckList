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
* [ ] Session ID Content (or Value): The session ID content (or value) must be meaningless to prevent information disclosure attacks, where an attacker is able to decode the contents of the ID and extract details of the user, the session, or the inner workings of the web application.
* [ ] Session Management Implementation
* [ ] Built-in Session Management Implementations:
The storage capabilities or repository used by the session management mechanism to temporarily save the session IDs must be secure, protecting the session IDs against local or remote accidental disclosure or unauthorized access.
* [ ] Used vs. Accepted Session ID Exchange Mechanisms: A web application should make use of cookies for session ID exchange management. If a user submits a session ID through a different exchange mechanism, such as a URL parameter, the web application should avoid accepting it as part of a defensive strategy to stop session fixation.
* [ ] Transport Layer Securityn order to protect the session ID exchange from active eavesdropping and passive disclosure in the network traffic, it is mandatory to use an encrypted HTTPS (SSL/TLS) connection for the entire web session, not only for the authentication process where the user credentials are exchanged.
* [ ] The following set of HTTPS (SSL/TLS) best practices are focused on protecting the session ID (specifically when cookies are used) and helping with the integration of HTTPS within the web application:
    * [ ] Web applications should never switch a given session from HTTP to HTTPS, or viceversa, as this will disclose the session ID in the clear through the network.
    * [ ] Web applications should not mix encrypted and unencrypted contents (HTML pages, images, CSS, Javascript files, etc) on the same host (or even domain - see the “domain” cookie attribute), as the request of any web object over an unencrypted channel might disclose the session ID.
    * [ ] Web applications, in general, should not offer public unencrypted contents and private encrypted contents from the same host. It is recommended to instead use two different hosts, such as www.example.com over HTTP (unencrypted) for the public contents, and secure.example.com over HTTPS (encrypted) for the private and sensitive contents (where sessions exist). The former host only has port TCP/80 open, while the later only has port TCP/443 open.
    * [ ] Web applications should avoid the extremely common HTTP to HTTPS redirection on the home page (using a 30x HTTP response), as this single unprotected HTTP request/response exchange can be used by an attacker to gather (or fix) a valid session ID.
    * [ ] Web applications should make use of “HTTP Strict Transport Security (HSTS)” (previously called STS) to enforce HTTPS connections.
* [ ] Input/Data validation (XSS, SQL injections, XML injections, client side and server side validations, etc)
* [ ] Encryption (storage, transmission)
* [ ] Application server hardening (IIS, Apache)
* [ ] Use of CAPTCHA
* [ ] Logging for user actions and protection of logs
* [ ] A1 Injection
* [ ] A3 Cross-Site Scripting (XSS) (was formerly 2010-A2)
* [ ] A4 Insecure Direct Object References
* [ ] A5 Security Misconfiguration (was formerly 2010-A6)
* [ ] A6 Sensitive Data Exposure (2010-A7 Insecure Cryptographic Storage and 2010-A9 Insufficient Transport Layer Protection were merged to form 2013-A6)
* [ ] A7 Missing Function Level Access Control (renamed/broadened from 2010-A8 Failure to Restrict URL Access)
* [ ] A8 Cross-Site Request Forgery (CSRF) (was formerly 2010-A5)
* [ ] A9 Using Components with Known Vulnerabilities (new but was part of 2010-A6 – Security Misconfiguration)
* [ ] A10 Unvalidated Redirects and Forwards

## PCI DSS (Credit/Debit Card Handling) in applications
Essentially, requirements 3, 4, 6, 8, 10 of the PCI DSS Standard version 3.1
### Requirement 3: Protect stored cardholder data
* [ ] 3.1 - Keep cardholder data storage to a minimum by implementing data retention and disposal policies, procedures and processes that include at least the following for all cardholder data (CHD) storage: 
     * [ ] Limiting data storage amount and retention time to that which is required for legal, regulatory, and/or business requirements 
     * [ ] Specific retention requirements for cardholder data 
     * [ ] Processes for secure deletion of data when no longer needed 
     * [ ] A quarterly process for identifying and securely deleting stored cardholder data that exceeds defined retention.
* [ ] 3.1a - Examine the data retention and disposal policies, procedures and processes to verify they include the following for all cardholder data (CHD) storage:
Limiting data storage amount and retention time to that which is required for legal, regulatory, and/or business requirements.
Specific requirements for retention of cardholder data (for example, cardholder data needs to be held for X period for Y business reasons).
Processes for secure deletion of cardholder data when no longer needed for legal, regulatory, or business reasons. 
A quarterly process for identifying and securely deleting stored cardholder data that exceeds defined retention requirements.
* [ ] 3.1c - For a sample of system components that store cardholder data:
Examine files and system records to verify that the data stored does not exceed the requirements defined in the data retention policy 
     * [ ] Observe the deletion mechanism to verify data is deleted securely.
* [ ] 3.2 - Do not store sensitive authentication data after authorization (even if encrypted). If sensitive authentication data is received, render all data unrecoverable upon completion of the authorization process.
* [ ] 3.2.1 - Do not store the full contents of any track (from the magnetic stripe located on the back of a card, equivalent data contained on a chip, or elsewhere) after authorization. This data is alternatively called full track, track, track 1, track 2, and magneticstripe data.
* [ ] 3.2.2 - Do not store the card verification code or value (three-digit or four-digit number printed on the front or back of a payment card used to verify card-notpresent transactions) after authorization.
* [ ] 3.2.3 - Do not store the personal identification number (PIN) or the encrypted PIN block after authorization.
* [ ] 3.3 - Mask PAN when displayed (the first six and last four digits are the maximum number of digits to be displayed), such that only personnel with a legitimate business need can see the full PAN
* [ ] 3.3a - Examine written policies and procedures for masking the display of PANs to verify: 
     * [ ] A list of roles that need access to displays of full PAN is documented, together with a legitimate business need for each role to have such access. 
     * [ ] PAN must be masked when displayed such that only personnel with a legitimate business need can see the full PAN. 
     * [ ] All other roles not specifically authorized to see the full PAN must only see masked PANs.
* [ ] 3.3b - Examine system configurations to verify that full PAN is only displayed for users/roles with a documented business need, and that PAN is masked for all other requests.
* [ ] 3.3c - Examine displays of PAN (for example, on screen, on paper receipts) to verify that PANs are masked when displaying cardholder data, and that only those with a legitimate business need are able to see full PAN.
* [ ] 3.4 - Render PAN unreadable anywhere it is stored (including on portable digital media, backup media, and in logs) by using any of the following approaches:
One-way hashes based on strong cryptography, (hash must be of the entire PAN)
Truncation (hashing cannot be used to replace the truncated segment of PAN)
Index tokens and pads (pads must be securely stored)
Strong cryptography with associated key-management processes and procedures.
* [ ] 3.4.1 - If disk encryption is used (rather than file- or column-level database encryption), logical access must be managed separately and independently of native operating system authentication and access control mechanisms (for example, by not using local user account databases or general network login credentials). Decryption keys must not be associated with user accounts.
* [ ] 3.5 - Examine key-management policies and procedures to verify processes are specified to protect keys used for encryption of cardholder data against disclosure and misuse and include at least the following: 
Access to keys is restricted to the fewest number of custodians necessary.
Key-encrypting keys are at least as strong as the dataencrypting keys they protect.
Key-encrypting keys are stored separately from dataencrypting keys. 
Keys are stored securely in the fewest possible locations and forms.
* [ ] 3.5.1 - Examine user access lists to verify that access to keys is restricted to the fewest number of custodians necessary.
* [ ] 3.5.2 - Examine documented procedures to verify that cryptographic keys used to encrypt/decrypt cardholder data must only exist in one (or more) of the following forms at all times.
Encrypted with a key-encrypting key that is at least as strong as the data-encrypting key, and that is stored separately from the data-encrypting key
Within a secure cryptographic device (such as a hardware (host) security module (HSM) or PTS-approved point-of-interaction device)
* [ ] 3.5.2b - Examine system configurations and key storage locations to verify that cryptographic keys used to encrypt/decrypt cardholder data exist in one (or more) of the following form at all times.
Encrypted with a key-encrypting key
Within a secure cryptographic device (such as a hardware (host) security module (HSM) or PTS-approved point-of-interaction device)
* [ ] 3.5.3 - Store cryptographic keys in the fewest possible locations. 
* [ ] 3.6.a Additional testing procedure for service provider assessments only: If the service provider shares keys with their customers for transmission or storage of cardholder data, examine the documentation that the service provider provides to their customers to verify that it includes guidance on how to securely transmit, store, and update customers’ keys, in accordance with Requirements 3.6.1 through 3.6.8 below.
* [ ] 3.6.1.a Verify that key-management procedures specify how to generate strong keys. 
* [ ] 3.6.1.b Observe the method for generating keys to verify that strong keys are generated. 
* [ ] 3.6.2.a Verify that key-management procedures specify how to securely distribute keys.
* [ ] 3.6.2.b Observe the method for distributing keys to verify that keys are distributed securely.
* [ ] 3.6.3.a Verify that key-management procedures specify how to securely store keys.
* [ ] 3.6.3.b Observe the method for storing keys to verify that keys are stored securely. 
* [ ] 3.6.5.a Verify that key-management procedures specify processes for the following:
The retirement or replacement of keys when the integrity of the key has been weakened
The replacement of known or suspected compromised keys.
Any keys retained after retiring or replacing are not used for encryption operations 
* [ ] 3.6.6.a Verify that manual clear-text key-management procedures specify processes for the use of the following:
Split knowledge of keys, such that key components are under the control of at least two people who only have knowledge of their own key components; AND 
Dual control of keys, such that at least two people are required to perform any key-management operations and no one person has access to the authentication materials (for example, passwords or keys) of another
* [ ] 3.6.7.a Verify that key-management procedures specify processes to prevent unauthorized substitution of keys

### Requirement 4: Encrypt transmission of cardholder data across open, public networks
* [ ] 4.1 Use strong cryptography and security protocols (for example, TLS, IPSEC, SSH, etc.) to safeguard sensitive cardholder data during transmission over open, public networks, including the following:
    * [ ] Only trusted keys and certificates are accepted. 
    * [ ] The protocol in use only supports secure versions or configurations. 
    * [ ] The encryption strength is appropriate for the encryption methodology in use.
* [ ] 4.1.c Select and observe a sample of inbound and outbound transmissions as they occur to verify that all cardholder data is encrypted with strong cryptography during transit.
* [ ] 4.1.d Examine keys and certificates to verify that only trusted keys and/or certificates are accepted. 
* [ ] 4.1.g For TLS implementations, examine system configurations to verify that TLS is enabled whenever cardholder data is transmitted or received. For example, for browser-based implementations: 
    * [ ] “HTTPS” appears as the browser Universal Record Locator (URL) protocol, and
    * [ ] Cardholder data is only requested if “HTTPS” appears as part of the URL.
* [ ] 4.1.i For all other environments using SSL and/or early TLS: Review the documented Risk Mitigation and Migration Plan to verify it includes:
    * [ ] Description of usage, including what data is being transmitted, types and number of systems that use and/or support SSL/early TLS, type of environment;
    * [ ] Risk-assessment results and risk-reduction controls in place; 
    * [ ] Description of processes to monitor for new vulnerabilities associated with SSL/early TLS; 
    * [ ] Description of change control processes that are implemented to ensure SSL/early TLS is not implemented into new environments; 
    * [ ] Overview of migration project plan including target migration completion date no later than June 30, 2016
* [ ] 4.2.a If end-user messaging technologies are used to send cardholder data, observe processes for sending PAN and examine a sample of outbound transmissions as they occur to verify that PAN is rendered unreadable or secured with strong cryptography whenever it is sent via end-user messaging technologies.
* [ ] 4.2.b Review written policies to verify the existence of a policy stating that unprotected PANs are not to be sent via end-user messaging technologies.

### Requirement 6: Develop and maintain secure systems and applications
* [ ] 6.1.a Examine policies and procedures to verify that processes are defined for the following: 
        * [ ] To identify new security vulnerabilities 
        * [ ] To assign a risk ranking to vulnerabilities that includes identification of all “high risk” and “critical” vulnerabilities. 
        * [ ] To use reputable outside sources for security vulnerability information.
* [ ] 6.2.a Examine policies and procedures related to securitypatch installation to verify processes are defined for: 
        * [ ] Installation of applicable critical vendor-supplied security patches within one month of release. 
        * [ ] Installation of all applicable vendor-supplied security patches within an appropriate time frame (for example, within three months).
* [ ] 6.2.b For a sample of system components and related software, compare the list of security patches installed on each system to the most recent vendor security-patch list, to verify the following: 
        * [ ] That applicable critical vendor-supplied security patches are installed within one month of release. 
        * [ ] All applicable vendor-supplied security patches are installed within an appropriate time frame (for example, within three months).
* [ ] 6.3.a Examine written software-development processes to verify that the processes are based on industry standards and/or best practices.
* [ ] 6.3.b Examine written software-development processes to verify that information security is included throughout the life cycle.
* [ ] 6.3.c Examine written software-development processes to verify that software applications are developed in accordance with PCI DSS.
* [ ] 6.3.1 Examine written software-development procedures and interview responsible personnel to verify that preproduction and/or custom application accounts, user IDs and/or passwords are removed before an application goes into production or is released to customers.
* [ ] 6.3.2.a Examine written software-development procedures and interview responsible personnel to verify that all custom application code changes must be reviewed (using either manual or automated processes) as follows:
    * [ ] Code changes are reviewed by individuals other than the originating code author, and by individuals who are knowledgeable in code-review techniques and secure coding practices.
    * [ ] Code reviews ensure code is developed according to secure coding guidelines (see PCI DSS Requirement 6.5).
    * [ ] Appropriate corrections are implemented prior to release.
    * [ ] Code-review results are reviewed and approved by management prior to release.
* [ ] 6.4 Examine policies and procedures to verify the following are defined: 
    * [ ] Development/test environments are separate from production environments with access control in place to enforce separation.
    * [ ] A separation of duties between personnel assigned to the development/test environments and those assigned to the production environment.
    * [ ] Production data (live PANs) are not used for testing or development. 
    * [ ] Test data and accounts are removed before a production system becomes active. 
    * [ ] Change control procedures related to implementing security patches and software modifications are documented.
* [ ] 6.4.1.a Examine network documentation and network device configurations to verify that the development/test environments are separate from the production environment(s)
* [ ] 6.4.1.b Examine access controls settings to verify that access controls are in place to enforce separation between the development/test environments and the production environment(s).
* [ ] 6.4.3.a Observe testing processes and interview personnel to verify procedures are in place to ensure production data (live PANs) are not used for testing or development.
* [ ] 6.4.4.a Observe testing processes and interview personnel to verify test data and accounts are removed before a production system becomes active.
* [ ] 6.4.5.a Examine documented change control procedures related to implementing security patches and software modifications and verify procedures are defined for: 
    * [ ] Documentation of impact
    * [ ] Documented change approval by authorized parties
    * [ ] Functionality testing to verify that the change does not adversely impact the security of the system
    * [ ] Back-out procedures
* [ ] 6.4.5.2 Verify that documented approval by authorized parties is present for each sampled change.
* [ ] 6.4.5.3.a For each sampled change, verify that functionality testing is performed to verify that the change does not adversely impact the security of the system.
* [ ] 6.4.5.3.b For custom code changes, verify that all updates are tested for compliance with PCI DSS Requirement 6.5 before being deployed into production
* [ ] 6.4.5.4 Verify that back-out procedures are prepared for each sampled change.
* [ ] 6.5.a Examine software-development policies and procedures to verify that training in secure coding techniques is required for developers, based on industry best practices and guidance.
* [ ] 6.5.c Examine records of training to verify that software developers received training on secure coding techniques, including how to avoid common coding vulnerabilities, and understanding how sensitive data is handled in memory.
    * [ ] 
* [ ] 6.5.1 Injectionflaws, especially SQL - Examine software-development policies and procedures and interview responsible personnel to verify that injection flaws are addressed by coding techniques that include: 
    * [ ] Validating input to verify user data cannot modify meaning of commands and queries.
    * [ ] Utilizing parameterized queries.
* [ ] 6.5.2 Buffer overflows - Examine software-development policies and procedures and interview responsible personnel to verify that buffer overflows are addressed by coding techniques that include: 
    * [ ] Validating buffer boundaries. 
    * [ ] Truncating input strings.
* [ ] 6.5.3 Insecure cryptographic storage Examine software-development policies and procedures and interview responsible personnel to verify that insecure cryptographic storage is addressed by coding techniques that: 
        * [ ] Prevent cryptographic flaws. 
        * [ ] * [ ] Use strong cryptographic algorithms and keys.
* [ ] 6.5.4 Insecure communications - Examine software-development policies and procedures and interview responsible personnel to verify that insecure communications are addressed by coding techniques that properly authenticate and encrypt all sensitive communications.
* [ ] 6.5.5 Improper error handling - Examine software-development policies and procedures and interview responsible personnel to verify that improper error handling is addressed by coding techniques that do not leak information via error messages (for example, by returning generic rather than specific error details).
* [ ] 6.5.6 Examine software-development policies and procedures and interview responsible personnel to verify that coding techniques address any “high risk” vulnerabilities that could affect the application, as identified in PCI DSS Requirement 6.1.
* [ ] 6.5.7 Cross-site scripting (XSS) - Examine software-development policies and procedures and interview responsible personnel to verify that cross-site scripting (XSS) is addressed by coding techniques that include
    * [ ] Validating all parameters before inclusion
    * [ ] Utilizing context-sensitive escaping.
* [ ] 6.5.8 Improper access control (such as insecure direct object references, failure to restrict URL access, directory traversal, and failure to restrict user access to functions). Examine software-development policies and procedures and interview responsible personnel to verify that improper access control—such as insecure direct object references, failure to restrict URL access, and directory traversal—is addressed by coding technique that includes: 
    * [ ] Proper authentication of users 
    * [ ] Sanitizing input 
    * [ ] Not exposing internal object references to users 
    * [ ] User interfaces that do not permit access to unauthorized functions.
* [ ] 6.5.9 Cross-site request forgery (CSRF) - Examine software development policies and procedures and interview responsible personnel to verify that cross-site request forgery (CSRF) is addressed by coding techniques that ensure applications do not rely on authorization credentials and tokens automatically submitted by browsers.
* [ ] 6.5.10 Broken authentication and session managementNote: Requirement 6.5.10 is a best practice until June 30, 2015, after which it becomes a requirement. 6.5.10 Examine software development policies and procedures and interview responsible personnel to verify that broken authentication and session management are addressed via coding techniques that commonly include: 
    * [ ] Flagging session tokens (for example cookies) as “secure” 
    * [ ] Not exposing session IDs in the URL 
    * [ ] Incorporating appropriate time-outs and rotation of session IDs after a successful login
* [ ] 6.6 For public-facing web applications, ensure that either one of the following methods is in place as follows:
    * [ ] Examine documented processes, interview personnel, and examine records of application security assessments to verify that public-facing web applications are reviewed—using either manual or automated vulnerability security assessment tools or methods—as follows: - At least annually - After any changes - By an organization that specializes in application security - That, at a minimum, all vulnerabilities in Requirement 6.5 are included in the assessment - That all vulnerabilities are corrected - That the application is re-evaluated after the corrections. 
    * [ ] Examine the system configuration settings and interview responsible personnel to verify that an automated technical solution that detects and prevents web-based attacks (for example, a web-application firewall) is in place as follows: - Is situated in front of public-facing web applications to detect and prevent web-based attacks. - Is actively running and up to date as applicable. - Is generating audit logs. - Is configured to either block web-based attacks, or generate an alert that is immediately investigated.
* [ ] 6.7 Examine documentation and interview personnel to verify that security policies and operational procedures for developing and maintaining secure systems and applications are: 
    * [ ] Documented, 
    * [ ] In use, and 
    * [ ] Known to all affected parties.
