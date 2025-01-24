import json
import asyncio
from api.ssl_certificate import fetch_ssl_certificate
from api.dnssec_records import fetch_dnssec_records
from api.threats import handle_threat_checks
from api.security_headers import check_security_headers
from api.tls_check import check_tls  
from api.http_headers import fetch_http_headers
from api.Firewall import detect_waf
from api.port import ports_handler

THRESHOLDS = {
    'SAFE':    60,  # 60%
    'WARNING': 30   # 30%
    # Below 30% is UNSAFE
}

PORT_WEIGHTS = {
    20: 4, 21: 5, 22: 4, 23: 6, 25: 3, 53: 3, 67: 3, 68: 3, 69: 3, 80: 4, 110: 3, 119: 3, 123: 3, 143: 3, 156: 4, 161: 4, 162: 4, 179: 3, 194: 3, 389: 5, 443: 2, 587: 3, 993: 2, 995: 2, 3000: 4, 3306: 5, 3389: 6, 5060: 4, 5900: 5, 8000: 3, 8080: 3, 8888: 3
}

PORT_VULNERABILITIES = {
    20: {
        "risk":"""\nPort 20 (FTP Data) is exploited due to:\n1. Unencrypted Data Transfers (High Risk): Data is transmitted without encryption, making it easy for attackers to intercept sensitive information.\n2. Weak Authentication (Medium Risk): FTP often uses basic authentication, making brute-force attacks feasible.\n""",
        "suggestion": """\n1. Disable FTP if not needed.\n2. Use SFTP for encrypted transfers and stronger authentication."""
    },
    21: {
        "risk":"""\nPort 21 (FTP) is prone to:\n1. Unencrypted Data Transfers (High Risk): FTP sends credentials and files in plain text.\n2. Brute-force Attacks (Medium Risk): Password-guessing attacks are common due to weak authentication.\n""",
        "suggestion": """\n1. Replace FTP with SFTP or FTPS to secure both data and authentication.\n2. Ensure strong passwords and limit failed login attempts."""
    },
    22: {
        "risk":"""\nPort 22 (SSH) faces:\n1. Brute-force Attacks (High Risk): Attackers may try to gain access by guessing passwords.\n2. Credential Compromise (Medium Risk): If weak credentials are used, attackers can gain unauthorized access.\n""",
        "suggestion": """\n1. Use SSH keys instead of passwords.\n2. Enable two-factor authentication and rate-limiting on failed login attempts."""
    },
    23: {
        "risk":"""\nPort 23 (Telnet) is insecure due to:\n1. Unencrypted Communication (High Risk): All data, including login credentials, is sent in plain text.\n2. MITM Attacks (High Risk): Attackers can intercept and alter communications.\n""",
        "suggestion": """\n1. Disable Telnet and replace it with SSH for encrypted remote communication.\n2. Use strong encryption protocols like SSH for secure access."""
    },
    25: {
        "risk":"""\nPort 25 (SMTP) is abused for:\n1. Spam and Open Relay Attacks (High Risk): SMTP servers can be misused to send spam.\n2. No Encryption (Medium Risk): If not configured with TLS, SMTP traffic can be intercepted.\n""",
        "suggestion": """\n1. Use proper authentication and encryption (TLS) for SMTP.\n2. Close open relays and monitor SMTP logs for abnormal activities."""
    },
    53: {
        "risk":"""\nPort 53 (DNS) is targeted for:\n1. DNS Amplification Attacks (High Risk): Open DNS resolvers can be misused for DDoS.\n2. DNS Hijacking (Medium Risk): Attackers may manipulate DNS responses to redirect traffic.\n""",
        "suggestion": """\n1. Implement DNSSEC to validate DNS responses.\n2. Restrict external DNS queries to trusted sources."""
    },
    67: {
        "risk":"""\nPort 67 (DHCP server) is vulnerable to:\n1. DHCP Spoofing (High Risk): Rogue DHCP servers can mislead clients into joining a malicious network.\n2. DoS Attacks (Medium Risk): DHCP servers can be overloaded or disrupted by attackers.\n""",
        "suggestion": """\n1. Restrict DHCP responses to trusted devices.\n2. Monitor for rogue DHCP servers on the network."""
    },
    68: {
        "risk":"""\nPort 68 (DHCP client) can be exploited for:\n1. Rogue DHCP Servers (High Risk): Attackers can redirect network traffic by providing false IP addresses.\n2. MITM Attacks (Medium Risk): Fake DHCP responses can reroute traffic to malicious servers.\n""",
        "suggestion": """\n1. Ensure clients only accept DHCP responses from trusted sources.\n2. Monitor and block rogue DHCP servers on the network."""
    },
    69: {
        "risk":"""\nPort 69 (TFTP) lacks security features:\n1. Unencrypted Data (High Risk): Files transmitted via TFTP are not encrypted, making them easy to intercept.\n2. No Authentication (Medium Risk): TFTP doesn't require authentication, allowing unauthorized access.\n""",
        "suggestion": """\n1. Replace TFTP with a more secure protocol like SFTP.\n2. Use firewalls to restrict access to TFTP servers."""
    },
    80: {
        "risk":"""\nPort 80 (HTTP) is susceptible to:\n1. Unencrypted Traffic (High Risk): HTTP transmits data in plain text, exposing it to interception.\n2. MITM Attacks (High Risk): Attackers can intercept and modify HTTP requests and responses.\n""",
        "suggestion": """\n1. Redirect HTTP to HTTPS to ensure encrypted communication.\n2. Use strong TLS configurations to secure all traffic."""
    },
    110: {
        "risk":"""\nPort 110 (POP3) is insecure due to:\n1. Unencrypted Email (High Risk): POP3 transmits email credentials and content in plain text.\n2. Credential Theft (Medium Risk): Attackers can intercept and steal login credentials.\n""",
        "suggestion": """\n1. Replace POP3 with secure alternatives like POP3S (SSL).\n2. Enforce strong encryption for email transmission."""
    },
    119: {
        "risk":"""Port 119 (NNTP) is vulnerable to:\n1. Packet Sniffing (Medium Risk): NNTP data is sent unencrypted, allowing it to be captured by attackers.\n2. MITM Attacks (Medium Risk): Attackers can intercept NNTP traffic and manipulate it.\n""",
        "suggestion": """\n1. Use SSL/TLS for encrypted NNTP traffic.\n2. Restrict access to trusted networks only."""
    },
    123: {
        "risk":"""\nPort 123 (NTP) is vulnerable to:\n1. NTP Amplification Attacks (High Risk): NTP can be abused for DDoS attacks by amplifying traffic.\n2. Time Manipulation (Medium Risk): Attackers can tamper with NTP responses, affecting time-sensitive operations.\n""",
        "suggestion": """\n1. Restrict NTP requests to trusted IP addresses.\n2. Regularly update NTP software to patch known vulnerabilities."""
    },
    143: {
        "risk":"""\nPort 143 (IMAP) is targeted for:\n1. Unencrypted Email Retrieval (High Risk): IMAP transfers email without encryption, exposing it to interception.\n2. Credential Theft (Medium Risk): Attackers can capture IMAP credentials in transit.\n""",
        "suggestion": """\n1. Switch to IMAPS (SSL/TLS) for encrypted communication.\n2. Use strong authentication mechanisms for email accounts."""
    },
    156: {
        "risk":"""\nPort 156 (SQL Service) is vulnerable to:\n1. SQL Injection (High Risk): Attackers can exploit poorly sanitized queries to manipulate databases.\n2. Unauthorized Access (Medium Risk): If misconfigured, attackers can gain direct access to databases.\n""",
        "suggestion": """\n1. Restrict access to SQL services using firewalls.\n2. Sanitize all inputs to prevent SQL injection attacks."""
    },
    161: {
        "risk":"""\nPort 161 (SNMP) is commonly exploited for:\n1. Unauthorized Access (High Risk): SNMP is often misconfigured, allowing attackers to retrieve sensitive network information.\n2. Weak Encryption (Medium Risk): SNMPv1 and SNMPv2 use weak encryption, exposing data to interception.\n""",
        "suggestion": """\n1. Use SNMPv3 with encryption for secure communications.\n2. Disable SNMP if not required or limit it to trusted sources."""
    },
    162: {
        "risk":"""\nPort 162 (SNMP Trap) is vulnerable to:\n1. Unauthorized Monitoring (Medium Risk): SNMP traps can be intercepted, exposing sensitive network events.\n2. Weak Authentication (Medium Risk): Earlier versions of SNMP lack strong authentication.\n""",
        "suggestion": """\n1. Use SNMPv3 with encryption for secure SNMP traps.\n2. Restrict access to trusted devices only."""
    },
    179: {
        "risk":"""\nPort 179 (BGP) is vulnerable to:\n1. Route Hijacking (High Risk): Attackers can manipulate routing information to divert traffic.\n2. BGP Spoofing (Medium Risk): Misconfigured BGP connections can be exploited for man-in-the-middle attacks.\n""",
        "suggestion": """\n1. Ensure BGP connections are authenticated.\n2. Restrict BGP communications to trusted peers."""
    },
    194: {
        "risk":"""\nPort 194 (IRC) is abused for:\n1. Botnets and DDoS (High Risk): IRC channels are often used to control botnets and launch attacks.\n2. Unencrypted Communication (Medium Risk): IRC does not natively encrypt messages, making it vulnerable to interception.\n""",
        "suggestion": """\n1. Use encryption for IRC channels or avoid using IRC for critical communications.\n2. Restrict IRC to trusted networks only."""
    },
    389: {
        "risk":"""\nPort 389 (LDAP) is vulnerable to:\n1. LDAP Injection (High Risk): Unsanitized inputs can be exploited for unauthorized access or data manipulation.\n2. Unencrypted Communication (Medium Risk): LDAP data is sent unencrypted by default, exposing it to interception.\n""",
        "suggestion": """\n1. Use LDAPS (LDAP over SSL) to encrypt LDAP traffic.\n2. Enforce strict access controls and sanitize all inputs to prevent LDAP injection."""
    },
    443: {
        "risk":"""\nPort 443 (HTTPS) can be misconfigured for:\n1. Weak Encryption (High Risk): Poor TLS configurations may leave HTTPS vulnerable to attacks.\n2. Outdated Protocols (Medium Risk): SSL/TLS versions older than 1.2 may be insecure.\n""",
        "suggestion": """\n1. Use TLS 1.2 or higher and disable older versions of SSL/TLS.\n2. Implement HSTS to enforce HTTPS and prevent downgrade attacks."""
    },
    587: {
        "risk":"""\nPort 587 (SMTP-TLS) can be misconfigured for:\n1. Weak Encryption (Medium Risk): Older encryption methods may leave SMTP traffic vulnerable to attacks.\n2. Open Relay Attacks (Medium Risk): Misconfigured SMTP servers can be abused to send spam.\n""",
        "suggestion": """\n1. Enforce modern encryption standards for SMTP traffic.\n2. Close open relays and implement rate limiting to prevent abuse."""
    },
    993: {
        "risk":"""\nPort 993 (IMAPS) can be targeted for:\n1. Weak Encryption (Medium Risk): If not properly configured, IMAPS may expose email data.\n2. Man-in-the-Middle Attacks (Medium Risk): Attackers may exploit misconfigured SSL/TLS settings.\n""",
        "suggestion": """\n1. Ensure strong SSL/TLS configurations are in place for IMAPS.\n2. Regularly update SSL certificates and mail server software."""
    },
    995: {
        "risk":"""\nPort 995 (POP3S) can be misconfigured for:\n1. Weak Encryption (Medium Risk): Poor TLS settings may expose email data to attackers.\n2. Credential Theft (Medium Risk): Unsecured POP3S connections can lead to stolen credentials.\n""",
        "suggestion": """\n1. Use strong TLS encryption for POP3S.\n2. Regularly update mail server software to prevent vulnerabilities."""
    },
    3000: {
        "risk":"""\nPort 3000 (Custom services) is often exposed for:\n1. Brute-force Attacks (High Risk): Custom services running on port 3000 may lack security controls, making them susceptible to brute-force attempts.\n2. DoS Attacks (Medium Risk): Attackers can exploit vulnerabilities in custom applications to cause denial-of-service.\n""",
        "suggestion": """\n1. Restrict access to port 3000 using firewalls or IP whitelisting.\n2. Apply rate limiting and secure authentication for any custom services."""
    },
    3306: {
        "risk":"""\nPort 3306 (MySQL) is vulnerable to:\n1. SQL Injection (High Risk): Poorly sanitized inputs may lead to database compromise.\n2. Remote Exploitation (Medium Risk): If exposed, attackers can brute-force MySQL credentials.\n""",
        "suggestion": """\n1. Ensure MySQL is behind a firewall, and limit access to trusted IP addresses.\n2. Use strong credentials and disable remote root access."""
    },
    3389: {
        "risk":"""\nPort 3389 (RDP) is targeted for:\n1. Brute-force Attacks (High Risk): Attackers often attempt to gain access to RDP servers through credential stuffing.\n2. Ransomware (High Risk): RDP vulnerabilities are frequently exploited to deploy ransomware.\n""",
        "suggestion": """\n1. Disable RDP if not necessary, or secure it with two-factor authentication.\n2. Use strong passwords and enable account lockout after multiple failed attempts."""
    },
    5060: {
        "risk":"""\nPort 5060 (SIP) is susceptible to:\n1. VoIP Eavesdropping (High Risk): SIP traffic can be intercepted if not encrypted.\n2. Toll Fraud (High Risk): Attackers may exploit SIP vulnerabilities to make unauthorized calls.\n""",
        "suggestion": """\n1. Use encryption (TLS) for SIP traffic.\n2. Limit SIP access to trusted IP ranges."""
    },
    5900: {
        "risk":"""\nPort 5900 (VNC) is vulnerable to:\n1. Remote Access Exploits (High Risk): Attackers can gain unauthorized access if VNC is exposed to the internet.\n2. No Encryption (Medium Risk): VNC sessions are unencrypted by default, making them vulnerable to interception.\n""",
        "suggestion": """\n1. Use VNC over SSH or VPN to secure remote sessions.\n2. Implement strong authentication and encryption for VNC connections."""
    },
    8000: {
        "risk":"""\nPort 8000 (HTTP Alt) is often used for:\n1. Web Service Attacks (High Risk): Services running on port 8000 are prone to vulnerabilities like HTTP floods and DoS.\n2. Weak Authentication (Medium Risk): Custom web applications may lack strong authentication mechanisms.\n""",
        "suggestion": """\n1. Secure web services on port 8000 with encryption and proper authentication.\n2. Use rate limiting to prevent DoS attacks."""
    },
    8080: {
        "risk":"""\nPort 8080 (HTTP Proxy) can be misconfigured, leading to:\n1. Proxy Abuse (High Risk): Attackers may exploit misconfigurations to bypass security controls.\n2. Data Interception (Medium Risk): Unencrypted proxy traffic can be intercepted by attackers.\n""",
        "suggestion": """\n1. Ensure proper configurations for proxies running on port 8080.\n2. Use HTTPS to encrypt proxy traffic."""
    },
    8888: {
        "risk":"""\nPort 8888 (HTTP Alt) is used for:\n1. Proxies and Test Services (Medium Risk): These services are often exposed and vulnerable to exploits.\n2. Weak Security Configurations (Medium Risk): Test services may lack proper authentication and encryption.\n""",
        "suggestion": """\n1. Ensure services running on port 8888 are properly secured.\n2. Restrict access to trusted IP addresses and use HTTPS for secure connections."""
    }
}

RISKS_AND_SUGGESTIONS = {
    "SSL Certificate not Valid": {
        "risk": """\nExpired or Invalid SSL Certificate can result in the following consequences:\n1. Browser Warnings (High Risk): Most modern browsers will display a security warning if an SSL certificate is invalid, damaging user trust and reducing traffic.\n2. Man-in-the-Middle (MITM) Attacks (High Risk): An invalid SSL certificate can expose your website to MITM attacks, allowing attackers to intercept and alter communication.\n3. Weak Encryption (Medium Risk): Using weak or outdated encryption (e.g., SSL, TLS 1.0) can expose sensitive data, making it vulnerable to attacks like BEAST or POODLE.\n4. Search Engine Ranking (Low Risk): Invalid SSL certificates can reduce your website's SEO ranking due to Google's preference for secure HTTPS sites.\n""",
        "suggestion": """\nTo mitigate these risks, you should:\n1. Renew and Validate SSL Certificates: Ensure that your SSL certificate is always up-to-date and issued by a trusted Certificate Authority (CA).\n2. Implement HSTS: Use HTTP Strict Transport Security (HSTS) to force browsers to only connect using HTTPS.\n3. Use Strong Encryption: Enable TLS 1.2 or higher and disable weak ciphers such as RC4, 3DES, and export-grade ciphers.\n4. Regular Testing: Regularly test your SSL configuration with tools like SSL Labs' SSL Test to ensure that your certificates are valid and the encryption is strong."""
    },
    "DNSSEC Partially Enabled": {
        "risk": """\nWith partial DNSSEC implementation, your website remains vulnerable to several risks:\n1. DNS Spoofing or Cache Poisoning (Medium Risk): Incomplete DNSSEC implementation means certain DNS queries may still be susceptible to tampering or fake DNS responses, leading to malicious redirects.\n2. Man-in-the-Middle Attacks (Medium Risk): Some DNS data might not be fully authenticated, allowing attackers to potentially intercept or alter DNS queries for certain records.\n3. Availability Issues (Low Risk): Partially implemented DNSSEC can cause misconfigurations, leading to potential downtime or unreliability in DNS queries.\n""",
        "suggestion": """\nTo mitigate these risks:\n1. Fully Implement DNSSEC: Complete the deployment of DNSSEC across all relevant DNS records, ensuring that each DNS query is protected.\n2. Perform DNSSEC Audits: Regularly audit the DNSSEC setup to identify which records remain unprotected and update them accordingly.\n3. Monitor for Configuration Errors: Check DNS configurations for misalignments or incomplete protection that could cause downtime or partial DNS failures.\n4. Consider a Managed DNS Provider: If managing DNSSEC in-house is challenging, consider using a DNS provider that supports full DNSSEC implementation and monitoring.\n"""
    },
    "DNSSEC Disabled": {
        "risk": """\nWithout DNSSEC, your website is vulnerable to:\n1. DNS Spoofing or Cache Poisoning (High Risk): Attackers can modify or fake DNS responses, redirecting users to malicious websites.\n2. Man-in-the-Middle Attacks (Medium Risk): DNSSEC helps ensure that DNS data is authentic, preventing attackers from intercepting or altering DNS queries.3. Reputation Loss (Low Risk): Users may lose trust in the website if malicious redirects occur, leading to decreased traffic and possible legal issues.\n""",
        "suggestion": """\nTo prevent these risks:\n1. Enable DNSSEC: Ensure DNSSEC is enabled to protect against DNS tampering.\n2. Monitor DNS Regularly: Perform frequent DNS audits to ensure DNSSEC is functioning correctly and no unauthorized changes are made.\n3. Use a Secure DNS Provider: Choose DNS providers that support DNSSEC and offer robust security configurations."""
    },
    "Malicious Threats Detected": {
        "risk": """\nIf malicious threats are detected on your website, the risks include:\n1. Malware Infections (High Risk): Users may download malware, leading to potential legal liabilities and a significant loss of trust in your website.\n2. Phishing Campaigns (High Risk): A compromised website could be used to run phishing campaigns, which may damage your brand reputation and result in penalties from search engines.\n3. Search Engine Blacklisting (Medium Risk): If search engines detect malware on your site, they may blacklist it, drastically reducing traffic.\n4. Legal and Regulatory Consequences (High Risk): Depending on your jurisdiction, hosting malware can result in legal penalties and violations of privacy regulations such as GDPR.\n""",
        "suggestion": """\nTo protect againt these threats:\n1. Use a Web Application Firewall (WAF): Implement a WAF to detect and block malicious traffic and prevent malware injections.\n2. Regular Malware Scans: Use tools like VirusTotal, Sucuri, or Wordfence to regularly scan your website for malware and vulnerabilities.\n3. Strengthen Authentication: Enforce strong authentication mechanisms (e.g., two-factor authentication) for admin access to minimize unauthorized modifications.\n4. Regular Backups and Monitoring: Maintain secure backups and monitor the website for unusual activities to mitigate damage from potential compromises."""
    },
    "Security Headers 80% Present": {
        "risk": """\nWith most security headers present, your website still faces a moderate level of risk:\n1. Cross-Site Scripting (XSS) Attacks (Medium Risk): If Content Security Policy (CSP) is missing, attackers could exploit XSS vulnerabilities by injecting malicious scripts.\n2. Data Leaks via Insecure Connections (Medium Risk): Without the Strict-Transport-Security (HSTS) header, browsers might not enforce HTTPS, leading to possible data exposure.\n""",
        "suggestion": """\nTo mitigate these risks:\n1. Implement Missing Security Headers: Add the missing security headers, particularly Content Security Policy (CSP) and HSTS, to strengthen your website's defenses.\n2. Audit Existing Headers: Ensure that the present headers are correctly configured to avoid potential vulnerabilities.\n3. Monitor for Attacks: Use security monitoring tools to detect XSS and other attacks that could exploit missing headers.\n"""
    },
    "Security Headers 60% Present": {
        "risk": """\nWith only 60% of the required security headers in place, your website is moderately exposed to several attack vectors:\n1. Cross-Site Scripting (XSS) Attacks (Medium Risk): A missing CSP header can allow attackers to inject and execute malicious scripts on your site.\n2. Clickjacking Attacks (Medium Risk): Without X-Frame-Options, attackers can embed your website in iframes to trick users into interacting with hidden or malicious content.\n3. Data Leaks (Medium Risk): Absence of HSTS may result in unencrypted communication over HTTP, exposing sensitive data.\n""",
        "suggestion": """\nTo improve security:\n1. Add Missing Headers: Implement missing headers like CSP, HSTS, and X-Frame-Options to minimize exposure to common attacks.\n2. Review Current Configurations: Ensure that the existing headers are correctly set up for all pages and endpoints.\n3. Conduct Regular Security Audits: Periodically review security settings to ensure they are properly applied and up-to-date.\n"""
    },
    "Security Headers 40% Present": {
        "risk": """\nWith only a few security headers implemented, your website is highly vulnerable to several types of attacks:\n1. Cross-Site Scripting (XSS) Attacks (High Risk): Missing CSP headers allow attackers to inject and execute harmful scripts.\n2. Clickjacking Attacks (High Risk): Without the X-Frame-Options header, your website is vulnerable to clickjacking, tricking users into interacting with malicious content embedded in iframes.\n3. Data Leaks (Medium Risk): Lack of HSTS may result in sensitive data being transferred over insecure connections (HTTP), leading to possible leaks.\n""",
        "suggestion": """\nTo minimize risks, take the following actions:\n1. Implement Key Security Headers: Add critical headers such as Content Security Policy (CSP), X-Frame-Options, and HSTS to protect your site against XSS, clickjacking, and insecure communications.\n2. Prioritize Header Setup: Ensure the headers are correctly configured and active on all web pages and services.\n3. Regular Security Monitoring: Use tools to actively monitor your site's security and detect any attack attempts that could exploit missing headers.\n"""
    },
    "Security Headers not Present": {
        "risk": """\nMissing security headers expose your website to:\n1. Cross-Site Scripting (XSS) Attacks (High Risk): Without Content Security Policy (CSP) headers, your website is vulnerable to XSS attacks where attackers can inject malicious scripts.\n2. Clickjacking Attacks (Medium Risk): The lack of X-Frame-Options headers leaves your site vulnerable to clickjacking attacks where users are tricked into clicking hidden elements.\n3. Open Redirects (Medium Risk): Attackers may exploit missing or misconfigured headers to redirect users to harmful sites.\n4. Data Leaks via Insecure Connections (Medium Risk): If the Strict-Transport-Security (HSTS) header is absent, browsers may not enforce HTTPS, allowing data to be exposed over insecure connections.\n""",
        "suggestion": """\nTo improve security, implement the following headers:\n1. Content Security Policy (CSP): Prevent XSS attacks by controlling which sources of content are trusted.\n2. X-Frame-Options: Prevent clickjacking attacks by disallowing your site from being embedded in iframes.\n3. Strict-Transport-Security (HSTS): Enforce HTTPS connections to prevent data leaks over HTTP.\n4. X-Content-Type-Options: Set this to "nosniff" to prevent MIME type sniffing attacks.5. Regular Header Audits: Regularly audit your security headers and adjust configurations based on best practices and new threats."""
    },
    "TLS not supported": {
        "risk": """\nThe absence of TLS support leaves your website vulnerable to:\n1. MITM Attacks (High Risk): Without TLS, attackers can intercept and alter data between the user and the server, leading to compromised information.\n2. Weak Encryption (Medium Risk): If TLS 1.0 or 1.1 is used, the connection is vulnerable to attacks like POODLE and BEAST, allowing attackers to decrypt sensitive data.\n3. Compliance Violations (High Risk): Many regulations such as GDPR require secure data transmission, and a lack of TLS may result in non-compliance penalties.\n""",
        "suggestion": """\nTo protect your data, ensure that TLS is enabled and properly configured:\n1. Use TLS 1.2 or 1.3: Disable outdated protocols (TLS 1.0/1.1) and enforce modern encryption standards.\n2. Configure Cipher Suites: Use secure ciphers and disable weak ones such as RC4 and 3DES.3. Regular Testing: Use tools like SSL Labs to test your TLS configuration and improve weak areas."""
    },
    "HTTP Headers are Invalid": {
        "risk": """\nInvalid HTTP headers pose several risks:\n1. MIME Sniffing (Medium Risk): Without the X-Content-Type-Options header, browsers may guess content types, which can lead to XSS attacks\n2. Cross-Site Scripting (XSS) (High Risk): Incorrect or missing HTTP headers can leave your site vulnerable to client-side attacks, such as XSS.\n3. Data Exposure (Medium Risk): Improper or missing headers may lead to the leakage of sensitive data over insecure connections.\n""",
        "suggestion": """\nTo resolve these issues:\n1. Set X-Content-Type-Options: Add "nosniff" to prevent MIME-type attacks.\n2. Implement Referrer-Policy: Control what information is shared through HTTP referrer headers.3. Audit Headers Regularly: Regularly test your headers with tools like SecurityHeaders.com and implement best practices to secure your website."""
    },
    "Firewall Disabled": {
        "risk": """\nWithout a firewall, your server is exposed to:\n1. Unfiltered Malicious Traffic (High Risk): Attackers can send malicious requests to your server, leading to data theft, website defacement, or system compromise.\n2. DDoS Attacks (High Risk): A firewall can mitigate the effects of Distributed Denial of Service (DDoS) attacks by filtering out harmful traffic.\n3. Brute-Force Attacks (Medium Risk): Attackers can attempt to guess passwords or exploit vulnerabilities without being blocked by a firewall.\n4. SQL Injection and Cross-Site Scripting (XSS) (High Risk): A WAF can detect and block common attack vectors such as SQL injection and XSS.\n""",
        "suggestion": """\nTo secure your website":\n1. Enable and Configure a Web Application Firewall (WAF): Use a WAF to filter out malicious traffic and prevent attacks like SQL injection and XSS.\n2. Update Firewall Rules: Regularly update your firewall rules based on current threats.\n3. Rate Limiting and IP Blocking: Implement rate limiting to protect against brute-force attacks and block malicious IP addresses."""
    }
}

def determine_verdict(score):
    if score >= THRESHOLDS['SAFE']:
        return 'SAFE'
    elif score >= THRESHOLDS['WARNING']:
        return 'WARNING'
    else:
        return 'UNSAFE' 

async def check_websites(url):
    ssl_certificate = fetch_ssl_certificate(url)
    dnssec_records = fetch_dnssec_records(url)
    threats = handle_threat_checks(url)
    security_headers = check_security_headers(url)
    tls_status = check_tls(url) 
    http_headers = fetch_http_headers(url) 
    firewall = detect_waf(url)
    ports = await ports_handler(url)

    Ssl = "Valid" if ssl_certificate else "Invalid"

    count_dnssec = sum([dnssec_records['DNSKEY']['isFound'] == True, dnssec_records['DS']['isFound'] == True, dnssec_records['RRSIG']['isFound'] == True])
    Dnssec = "Enabled" if count_dnssec == 3 else "Partially Enabled" if count_dnssec == 2 else "Disabled"

    Threats = "None" if threats['urlhaus']['query_status'] == 'no_results' and threats['phishtank']['url0'] == 'false' else "Detected"

    count_security = sum([security_headers['strictTransportPolicy'] == True, security_headers['xFrameOptions'] == True, security_headers['xContentTypeOptions'] == True, security_headers['xXSSProtection'] == True, security_headers['contentSecurityPolicy'] == True])
    Security = "Present" if count_security == 5 else "80% Present" if count_security == 4 else "60% Present" if count_security == 3 else "40% Present" if count_security == 2 else "Not Present"

    Tls = "Supported" if tls_status else "Not Supported"

    Http = "Valid" if http_headers else "Invalid"
    
    Firewall = "Enabled" if firewall['hasWaf'] == 'True' else "Disabled"
    
    open_ports = ports['open_ports']

    results = [Ssl, Dnssec, Threats, Security, Tls, Http, Firewall, open_ports]
    score, explanations = calculate_score(*results)
    verdict = determine_verdict(score)
    return format_risks_and_suggestions(score, verdict, explanations)

def calculate_score(SSL_status, DNSSEC_status, Threats_status, Security_Headers_status, TLS_status, HTTP_Headers_status, Firewall_status, Ports):
    score = 0
    explanations = []

    if SSL_status == "Valid":
        score += 25 
    elif SSL_status == "Invalid":
        explanations.append("SSL Certificate not Valid")

    if DNSSEC_status == "Enabled":
        score += 15  
    elif DNSSEC_status == "Partially Enabled":
        score += 10  
        explanations.append("DNSSEC Partially Enabled")
    elif DNSSEC_status == "Disabled":
        explanations.append("DNSSEC Disabled")

    if Threats_status == "Detected":
        score -= 50 
        explanations.append("Malicious Threats Detected")

    if Security_Headers_status == "Present":
        score += 10
    elif Security_Headers_status == "80% Present":
        score += 8
        explanations.append("Security Headers 80% Present")
    elif Security_Headers_status == "60% Present":
        score += 6
        explanations.append("Security Headers 60% Present")
    elif Security_Headers_status == "40% Present":
        score += 4
        explanations.append("Security Headers 40% Present")
    elif Security_Headers_status == "Not Present":
        explanations.append("Security Headers not Present")

    if TLS_status == "Supported":
        score += 15  
    elif TLS_status == "Not Supported":
        explanations.append("TLS not supported")

    if HTTP_Headers_status == "Valid":
        score += 10 
    elif HTTP_Headers_status == "Invalid":
        explanations.append("HTTP Headers are Invalid")

    if Firewall_status == "Enabled":
        score += 15
    elif Firewall_status == "Disabled":
        explanations.append("Firewall Disabled")

    if not Ports:
        score += 10
    else:
        for port in Ports:
            if port in PORT_WEIGHTS:
                score -= PORT_WEIGHTS[port]
                explanations.append(f"Port {port} is open")

    return max(score, 0), explanations

def format_risks_and_suggestions(score, verdict, explanations):
    result = {"score": score, "verdict": verdict, "explanations": []}
    
    for explanation in explanations:
        explanation_data = {"explanation": explanation}
        
        if explanation.startswith("Port"):
            port = int(explanation.split()[1])
            risk = PORT_VULNERABILITIES.get(port, {}).get('risk', "No risk information available.")
            suggestion = PORT_VULNERABILITIES.get(port, {}).get('suggestion', "No suggestion available.")
        else:
            risk = RISKS_AND_SUGGESTIONS.get(explanation, {}).get('risk', "No risk information available.")
            suggestion = RISKS_AND_SUGGESTIONS.get(explanation, {}).get('suggestion', "No suggestion available.")
        
        explanation_data["risk"] = risk
        explanation_data["suggestion"] = suggestion
        result["explanations"].append(explanation_data)
    
    return json.dumps(result, indent=4)


# url = 'https://www.google.com'
# results = asyncio.run(check_websites(url))
# print(results)