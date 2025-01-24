
    function togglePopup(infoType) {
        const overlay = document.getElementById('overlay');
        const popup = document.getElementById('popup');
        const title = document.getElementById('popup-title');
        const content = document.getElementById('popup-content');

        if (infoType) {
            overlay.style.display = 'block';
            popup.style.display = 'block';

            
            switch (infoType) {
                case 'whoisInfo':
                    title.innerText = 'Domain WHOIS Information';
                    content.innerText = 'A query and response protocol used for querying databases that store registered users or assignees of a domain. A Whois lookup provides information about domain ownership, registration, and expiration dates.';
                    break;
                case 'dnsInfo':
                    title.innerText = 'DNS Data Information';
                    content.innerText = 'DNS data includes information about the domain name system records associated with the domain.';
                    break;
                case 'dnsRecordsInfo':
                    title.innerText = 'DNS Records Information';
                    content.innerText = 'Refers to Domain Name System records, which store information about domain names and IP addresses. DNS records include A records (IP address), MX records (mail servers), CNAME records (aliases), and more. These records are crucial for web traffic routing and service configuration.';
                    break;
                case 'dnssecInfo':
                    title.innerText = 'DNSSEC Information';
                    content.innerText = 'DNS Security Extensions ensure the integrity and authenticity of DNS data by providing cryptographic signatures. It protects against certain attacks, such as cache poisoning, by verifying that the DNS records are authentic and unaltered.';
                    break;
                case 'archivesInfo':
                    title.innerText = 'Archives Information';
                    content.innerText = 'This refers to stored versions of web pages, usually by web archiving services like the Wayback Machine. It allows checking past versions of a website, helpful for seeing changes over time or recovering lost information.';
                    break;
                case 'carbonInfo':
                    title.innerText = 'Carbon Footprint Information';
                    content.innerText = 'This calculates the environmental impact of a website in terms of CO₂ emissions. Websites can be assessed based on factors such as server energy usage, traffic, and efficiency to provide an estimate of their carbon footprint.';
                    break;
                case 'tlsCipherInfo':
                    title.innerText = 'TLS Cipher Suites Information';
                    content.innerText = 'A collection of encryption algorithms used during TLS/SSL communications. Checking cipher suites ensures that the server uses secure and up-to-date encryption protocols.';
                    break;
                case 'tlsHandshakeInfo':
                    title.innerText = 'TLS Handshake Simulation Information';
                    content.innerText = 'Simulates the TLS handshake process to ensure that a server properly negotiates secure connections with different clients or browsers. This checks for compatibility and security issues.';
                    break;
                case 'tlsSecurityInfo':
                    title.innerText = 'TLS Security Config Information';
                    content.innerText = 'Evaluates a server’s Transport Layer Security (TLS) setup, including supported versions, cipher suites, and overall strength, to ensure secure communication.';
                    break;
                case 'statusInfo':
                    title.innerText = 'Status Information';
                    content.innerText = 'Typically refers to the HTTP status codes returned by a website (e.g., 200 OK, 404 Not Found, 500 Internal Server Error). Checking the status helps identify issues with site availability or configuration.';
                    break;
                case 'tracerouteInfo':
                    title.innerText = 'Traceroute Information';
                    content.innerText = 'A diagnostic tool that tracks the path packets take to reach a server. Traceroute helps to troubleshoot network issues by identifying where delays or failures occur along the path.';
                    break;
                case 'blocklistsInfo':
                    title.innerText = 'Blocklists Information';
                    content.innerText = 'A list of domains or IP addresses that are known to be malicious or otherwise harmful. Websites or services can be checked against blocklists to see if they are flagged for issues like malware distribution, phishing, or spamming.';
                    break;
                case 'threatsInfo':
                    title.innerText = 'Threats Information';
                    content.innerText = 'Refers to known security threats like malware, phishing, or vulnerabilities affecting a website. This function may involve checking databases for reports of these threats on the domain.';
                    break;
                case 'openPortsInfo':
                    title.innerText = 'Open Ports Information';
                    content.innerText = 'Scans a server for open ports to determine which services are running. Open ports are potential entry points for attackers, so checking them can help identify security vulnerabilities.';
                    break;
                case 'pagesInfo':
                    title.innerText = 'Pages Information';
                    content.innerText = ' Refers to individual web pages hosted on a domain. This can involve crawling or analyzing the structure, content, and metadata of the pages within a site.';
                    break;
                case 'firewallInfo':
                    title.innerText = 'Firewall Information';
                    content.innerText = 'A security system that monitors and controls incoming and outgoing network traffic based on predefined security rules. For websites, firewalls can protect against unauthorized access, DDoS attacks, and other threats.';
                    break;
                case 'socialTagsInfo':
                    title.innerText = 'Social Tags Information';
                    content.innerText = 'Metadata used by social media platforms to display rich content previews when links are shared. These tags (like Open Graph or Twitter Cards) help ensure that links show images and descriptions when shared.';
                    break;
                case 'headersInfo':
                    title.innerText = 'Headers Information';
                    content.innerText = 'HTTP headers are metadata sent with web pages that provide information like the server type, content type, caching policies, and more. They are critical for web communication between clients (browsers) and servers.';
                    break;
                case 'hstsInfo':
                    title.innerText = 'HSTS Check Information';
                    content.innerText = 'HTTP Strict Transport Security (HSTS) ensures that browsers only connect to a site using HTTPS. Checking HSTS compliance ensures that a site is protected against certain downgrade attacks (e.g., SSL stripping).';
                    break;
                case 'httpSecurityInfo':
                    title.innerText = 'HTTP Security Information';
                    content.innerText = 'These are key-value pairs in the HTTP protocol, used to convey important information between clients and servers. HTTP headers manage things like content types, authentication, security settings, and caching.';
                    break;
                case 'domainInfo':
                    title.innerText = 'Domain Rank Information';
                    content.innerText = ' A score given to a domain based on its popularity, backlinks, and SEO metrics. This rank is often used to assess the authority or trustworthiness of a website relative to others..';
                    break;
                case 'trancoInfo':
                    title.innerText = 'Tranco Rank Information';
                    content.innerText = 'A ranking system similar to Alexa or Majestic, but focused on providing a high-quality list of the most popular domains based on long-term observations. It’s used for tracking a website’s popularity over time.';
                    break;
                case 'linkedPagesInfo':
                    title.innerText = 'Linked Pages Information';
                    content.innerText = 'This function identifies internal and external links on a webpage, helping to analyze the page’s structure, SEO performance, and link distribution.';
                    break;
                case 'mailServicesInfo':
                    title.innerText = 'Mail Services Information';
                    content.innerText = 'Checks the mail servers (MX records) associated with a domain and ensures that they are properly configured for handling emails, including security aspects like SPF, DKIM, and DMARC.';
                    break;
                case 'sslInfo':
                    title.innerText = 'SSL Certificate Information';
                    content.innerText = 'Digital certificates that verify a site’s identity and encrypt data sent between the site and its users. An SSL certificate check ensures that HTTPS is in place and certificates are valid and secure.';
                    break;
                case 'redirectsInfo':
                    title.innerText = 'Redirects Information';
                    content.innerText = 'Checks for HTTP redirects on a website (such as 301 or 302 redirects). Redirects can influence SEO and user experience, so analyzing them ensures they are configured properly.';
                    break;
                case 'securityTxtInfo':
                    title.innerText = 'Security TXT Data Information';
                    content.innerText = 'A file that provides security contact information and vulnerability disclosure policies for a website. It helps researchers or users report security issues responsibly.';
                    break;
                case 'robotsInfo':
                    title.innerText = 'Robots.txt Information';
                    content.innerText = 'A file used by websites to instruct search engine bots on which parts of the site they are allowed or disallowed to crawl. Checking the robots.txt file ensures it’s correctly configured for SEO and security.';
                    break;
                case 'screenshotInfo':
                    title.innerText = 'Screenshot Information';
                    content.innerText = 'Captures an image of how the website looks visually. This can be useful for visual verification, testing, or archiving purposes.';
                    break;
                case 'server-info':
                    title.innerText = 'Server Information';
                    content.innerText = "Identifies the physical location of the server hosting the website. Knowing the server's location can be relevant for compliance with data privacy laws, performance, and latency considerations.";
                    break;
                case 'score-metrics-info':
                    title.innerText = 'Score Metrics Information';
                    content.innerText = "The scoring functionality evaluates various website security features, such as DNSSEC records, security headers, and open ports. It checks for key attributes like DNSSEC, Malicious Threats, SSL Certificate and high-risk open ports. Based on the presence or absence of these features, it assigns scores, categorizing the site's security as fully secure, partially secure, or vulnerable, and provides risk assessments and suggestions for improvement.";
                    break;

            }
        } else {
            overlay.style.display = 'none';
            popup.style.display = 'none';
        }
    }


