function reloadData(endpoint, elementId, loadFunction, section) {
    const url_or_ip = document.getElementById('domainName').innerText;

    document.getElementById(elementId).innerHTML = `<div class="centre">
                    <l-trefoil
                    size="40"
                    stroke="4"
                    stroke-length="0.15"
                    bg-opacity="0.1"
                    speed="1.4"
                    color="#50fa7b">
                    </l-trefoil>
                </div>`;

    // Debugging log to check the loadFunction
    console.log('loadFunction:', loadFunction);
    console.log('Is loadFunction a function?', typeof loadFunction === 'function');

    fetch(endpoint, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ url_or_ip: url_or_ip })
    })
        .then(response => response.json())
        .then(data => {
            // Check if loadFunction is a function before calling
            if (typeof loadFunction === 'function') {
                loadFunction(data, elementId, section);
            } else {
                console.error('loadFunction is not a valid function');
                document.getElementById(elementId).innerText = 'Error: Invalid function.';
            }
        })
        .catch(error => {
            console.error('Error fetching data:', error);
            document.getElementById(elementId).innerText = 'Error loading data.';
        });
}

function capitalizeFirstLetter(string) {
    return string.charAt(0).toUpperCase() + string.slice(1);
}

async function load_whois(data, elementId) {
    const whois = document.getElementById(elementId);
    whois.innerHTML = ''; // Clear previous content

    if (data.whois_data) {
        const whoisData = data.whois_data;

        // Loop through the keys of the whois data object
        Object.keys(whoisData).forEach((key) => {
            let value = whoisData[key];

            // Handle different data types (Array, Object, or other)
            if (Array.isArray(value)) {
                value = value.join(", "); // Convert arrays to comma-separated strings
            } else if (typeof value === "object" && value !== null) {
                value = JSON.stringify(value, null, 2); // Convert objects to a readable JSON string
            }

            whois.innerHTML += `<strong>${capitalizeFirstLetter(key)}:</strong> ${value || "No data available"
                }<br><br>`;
        });
    } else {
        whois.innerHTML = "No whois data available";
    }
}

async function load_dns_data(data, elementId) {
    const dnsElement = document.getElementById(elementId);
    dnsElement.innerHTML = `<div id="dns_data"><strong>IP Address:</strong><div>${data.dns_data.ip}</div></div>`;
}

async function load_dns_records(data, elementId) {
    const dnsElement = document.getElementById(elementId);
    dnsElement.innerHTML = '';

    // Create a container for DNS records data
    const recordsContainer = document.createElement('div');
    recordsContainer.setAttribute('id', 'dns_records_data');

    Object.keys(data.dns_records_data).forEach((recordType) => {
        const records = data.dns_records_data[recordType];
        if (records.length > 0) {
            // Create a section for each record type
            const recordTypeDiv = document.createElement("details");

            // Create a summary element for the record type
            const summaryElement = document.createElement("summary");
            summaryElement.innerHTML = `<strong>${recordType}</strong>: ${records.length} record(s)`;
            recordTypeDiv.appendChild(summaryElement);

            // Create a container for individual records
            const recordsDiv = document.createElement("div");

            records.forEach((record) => {
                const recordDiv = document.createElement("div");
                recordDiv.innerHTML = `<br><strong>Address:</strong> ${record.address} <br/><strong>Name:</strong> ${record.name} <br/><strong>Type:</strong> ${record.type} <br/> `;
                recordsDiv.appendChild(recordDiv);
            });

            // Append the records div to the record type div
            recordTypeDiv.appendChild(recordsDiv);
            // Append the record type div to the records container
            recordsContainer.appendChild(recordTypeDiv);

            // Add a line break (horizontal rule) after each record type
            recordsContainer.appendChild(document.createElement("hr"));
        }
    });

    dnsElement.appendChild(recordsContainer);
}

async function load_dnssec_data(data, elementId) {
    const dnsElement = document.getElementById(elementId);
    dnsElement.innerHTML = '';

    // Create a container for DNSSEC data
    const dnssecDataContainer = document.createElement('div');
    dnssecDataContainer.setAttribute('id', 'dnssec_data');

    Object.keys(data.dnssec_data).forEach((recordType) => {
        const record = data.dnssec_data[recordType];
        const recordDiv = document.createElement("div");

        // Use the checkmark and cross icons based on isFound
        const statusIcon = record.isFound ? "✅ Yes" : "❌ No";
        recordDiv.innerHTML = `<strong>${recordType}:</strong> ${statusIcon}`;

        const answersDiv = document.createElement("div");

        if (record.isFound && record.answer) {
            record.answer.forEach((entry) => {
                const entryDiv = document.createElement("div");
                entryDiv.innerHTML = `<strong>Name:</strong> ${entry.name} <br/><strong>Data:</strong> ${entry.data} <br/><strong>TTL:</strong> ${entry.TTL} <br/><strong>Type:</strong> ${entry.type}<br/><br/>`;
                answersDiv.appendChild(entryDiv);
            });
        } else {
            answersDiv.innerHTML = `<p>No answers available for this record.</p>`;
        }

        recordDiv.appendChild(answersDiv);
        dnssecDataContainer.appendChild(recordDiv);
        dnssecDataContainer.appendChild(document.createElement("br")); // Add line gap between record types
    });

    dnsElement.appendChild(dnssecDataContainer);
}

async function load_wayback_data(data, elementId) {
    const waybackElement = document.getElementById(elementId);
    waybackElement.innerHTML = '';

    // Create a container for Wayback data
    const waybackDataContainer = document.createElement('div');
    waybackDataContainer.setAttribute('id', 'wayback_data');

    // General Info Section
    const generalInfo = [
        {
            label: "Average Page Size",
            value: data.wayback_data.average_page_size,
        },
        { label: "Change Count", value: data.wayback_data.change_count },
        { label: "First Scan", value: data.wayback_data.first_scan },
        { label: "Last Scan", value: data.wayback_data.last_scan },
        { label: "Scan URL", value: data.wayback_data.scan_url },
        { label: "Total Scans", value: data.wayback_data.total_scans },
    ];

    generalInfo.forEach((info) => {
        const infoDiv = document.createElement("div");
        infoDiv.innerHTML = `<strong>${info.label}:</strong> ${info.value}`;
        waybackDataContainer.appendChild(infoDiv);
    });

    // Line gap after general info
    waybackDataContainer.appendChild(document.createElement("br"));

    // Scan Frequency Section
    const scanFrequency = data.wayback_data.scan_frequency;
    const frequencyInfo = [
        { label: "Changes per Day", value: scanFrequency.changes_per_day },
        {
            label: "Days between Changes",
            value: scanFrequency.days_between_changes,
        },
        { label: "Days between Scans", value: scanFrequency.days_between_scans },
        { label: "Scans per Day", value: scanFrequency.scans_per_day },
    ];

    const frequencyDiv = document.createElement("div");
    frequencyDiv.innerHTML = `<strong>Scan Frequency:</strong>`;
    const frequencyRecordsDiv = document.createElement("div");

    frequencyInfo.forEach((freq) => {
        const freqDiv = document.createElement("div");
        freqDiv.innerHTML = `<strong>${freq.label}:</strong> ${freq.value}`;
        frequencyRecordsDiv.appendChild(freqDiv);
    });

    frequencyDiv.appendChild(frequencyRecordsDiv);
    waybackDataContainer.appendChild(frequencyDiv);

    // Line gap after scan frequency
    waybackDataContainer.appendChild(document.createElement("br"));

    waybackElement.appendChild(waybackDataContainer);
}

async function load_carbon_footprint(data, elementId) {
    const carbonFootprintElement = document.getElementById(elementId);
    carbonFootprintElement.innerHTML = ''; // Clear previous content

    // General Info Section
    const generalInfo = [
        { label: "Cleaner Than", value: data.carbon_footprint_data.cleanerThan },
        {
            label: "Green",
            value: data.carbon_footprint_data.green ? "Yes" : "No",
        },
        { label: "Rating", value: data.carbon_footprint_data.rating },
        { label: "Scan URL", value: data.carbon_footprint_data.scanUrl },
    ];

    const infoDiv = document.createElement("div");
    infoDiv.innerHTML = `<strong>General Info:</strong><br>`;
    carbonFootprintElement.appendChild(infoDiv);
    // Display General Info
    generalInfo.forEach((info) => {
        const inDiv = document.createElement("div");
        inDiv.innerHTML = `<strong>${info.label}:</strong> ${info.value}<br>`;
        carbonFootprintElement.appendChild(inDiv);
    });

    // Line gap after general info
    carbonFootprintElement.appendChild(document.createElement("hr"));

    // Statistics Section
    const statistics = data.carbon_footprint_data.statistics;
    const co2 = statistics.co2;

    const statsDiv = document.createElement("div");
    statsDiv.innerHTML = `<strong>Statistics:</strong>`;
    carbonFootprintElement.appendChild(statsDiv);

    // Adjusted Bytes
    const adjustedBytesDiv = document.createElement("div");
    adjustedBytesDiv.innerHTML = `<strong>Adjusted Bytes:</strong> ${statistics.adjustedBytes}<br>`;
    carbonFootprintElement.appendChild(adjustedBytesDiv);
    carbonFootprintElement.appendChild(document.createElement("hr"));
    // CO2
    const co2Div = document.createElement("div");
    co2Div.innerHTML = `<strong>CO2:</strong>`;
    carbonFootprintElement.appendChild(co2Div);

    // Grid CO2
    const gridCo2Div = document.createElement("div");
    gridCo2Div.innerHTML = `<strong>Grid CO2:</strong><br/><strong>Grams:</strong> ${co2.grid.grams}<br/><strong>Litres:</strong> ${co2.grid.litres}<br><br>`;
    carbonFootprintElement.appendChild(gridCo2Div);

    // Renewable CO2
    const renewableCo2Div = document.createElement("div");
    renewableCo2Div.innerHTML = `<strong>Renewable CO2:</strong><br/><strong>Grams:</strong> ${co2.renewable.grams}<br/><strong>Litres:</strong> ${co2.renewable.litres}<br>`;
    carbonFootprintElement.appendChild(renewableCo2Div);

    carbonFootprintElement.appendChild(document.createElement("hr"));
    // Energy
    const energyDiv = document.createElement("div");
    energyDiv.innerHTML = `<strong>Energy:</strong> ${statistics.energy}<br>`;
    carbonFootprintElement.appendChild(energyDiv);
}

async function load_status(data, elementId) {
    const statusElement = document.getElementById(elementId);
    statusElement.innerHTML = ''; // Clear previous content

    // Check if status_data exists
    if (data && data.status_data) {
        const statusData = data.status_data;

        // Create HTML content in the desired format
        statusElement.innerHTML = `<div><strong>Is Up?</strong> : ${statusData.isUp ? "✅ Online" : "❌ Offline"}<br><br><strong>Status Code</strong> : ${statusData.responseCode || "No data available"}<br><br><strong>Response Time</strong> : ${statusData.responseTime ? `${statusData.responseTime} ms` : "No data available"}</div>`;
    } else {
        statusElement.innerHTML = "No status data available";
    }
}

async function load_traceroute(data, elementId) {
    const tracerouteElement = document.getElementById(elementId);

    // Check if traceroute data is present
    if (data.traceroute_data && Array.isArray(data.traceroute_data.result)) {
        // Create an HTML string to display the results
        let tracerouteHTML = `<h3 style="margin: 0;">Trace Route</h3>`;

        data.traceroute_data.result.forEach((hop, index) => {
            // Split the hop string to extract relevant data
            const parts = hop.match(
                /(\d+)\s+([\d\.]+|[*]+)\s+ms\s+([\d\.]+|[*]+)\s+ms\s+([\d\.]+|[*]+)\s+ms?\s+(.+)/
            );
            if (parts) {
                const hopNumber = parts[1]; // Hop number
                const responseTime1 = parts[2]; // Response time 1
                const hopAddress = parts[5]; // IP address or hostname

                tracerouteHTML += `<div>
                        <span class="trac">${hopAddress || "No IP"}</span>
                        <span style="color: #FFFFFF;"class="trac">Took ${responseTime1} ms (Hop ${hopNumber})</span>
                        ${index < data.traceroute_data.result.length - 1
                        ? '<span class="trac" style="font-size: xx-large;">↓</span>'
                        : ""}
                    </div>`;
            }
            // else {
            //     // For lines that do not match the expected format (e.g., "Request timed out.")
            //     tracerouteHTML += `<div><span style="color: #FFFFFF;" class="trac">${hop}</span><br></div>`;
            // }
        });

        // Add the completion message
        const message = data.traceroute_data.message || "No completion message";
        tracerouteHTML += `<p style="margin: 0;">${message}</p>`;

        // Display the collected traceroute data in the HTML element
        tracerouteElement.innerHTML = tracerouteHTML;
    } else {
        tracerouteElement.innerHTML =
            '<p style="margin: 0;">No traceroute data available.</p>';
    }
} //To be changed

async function load_blocklist(data, elementId) {
    const blocklistElement = document.getElementById(elementId);

    if (blocklistElement && data && data.blocklist_results) {
        const blocklistData = data.blocklist_results;

        // Render Blocklist Results in the desired format
        const blocklistHTML = blocklistData
            .map((result) => {
                const serverName = result.server; // Get the server name
                const isBlocked = result.is_blocked ? "✅ Blocked" : "✅ Not Blocked"; // Check if blocked

                return `<div>${serverName}<br>${isBlocked}</div>`;
            })
            .join("");

        // Display the blocklist results in formatted HTML
        blocklistElement.innerHTML = blocklistHTML;
    } else {
        blocklistElement.innerHTML = "<p>No blocklist results available.</p>";
    }
}

async function load_threats(data, elementId) {
    const securityElement = document.getElementById(elementId);
    securityElement.innerHTML = '';  // Clear previous content

    // PhishTank Section (Phishing Status)
    const phishTankDiv = document.createElement('div');
    const phishTankTitle = document.createElement('h3');
    phishTankTitle.textContent = 'Phishing Status';
    phishTankDiv.appendChild(phishTankTitle);

    if (data.threats_data && data.threats_data.phishtank) {
        const phishingFound = data.threats_data.phishtank.url0 === "true"; // Assuming the API has a key like this
        const phishingStatus = document.createElement("p");
        phishingStatus.innerHTML = phishingFound
            ? "❌ Phishing Detected"
            : "✅ No Phishing Found";
        phishTankDiv.appendChild(phishingStatus);
    } else {
        const noDataPhishTank = document.createElement("p");
        noDataPhishTank.textContent = "No data available";
        phishTankDiv.appendChild(noDataPhishTank);
    }

    securityElement.appendChild(phishTankDiv);
    securityElement.appendChild(document.createElement("br"));

    // URLHaus Section (Malware Status)
    const urlHausDiv = document.createElement("div");
    const urlHausTitle = document.createElement("h3");
    urlHausTitle.textContent = "Malware Status";
    urlHausDiv.appendChild(urlHausTitle);

    if (data.threats_data && data.threats_data.urlhaus) {
        const malwareFound = data.threats_data.urlhaus.query_status !== "no_results"; // Assuming the API has a key like this
        const malwareStatus = document.createElement("p");
        malwareStatus.innerHTML = malwareFound
            ? "❌ Malware Found"
            : "✅ No Malware Found";
        urlHausDiv.appendChild(malwareStatus);
    } else {
        const noDataURLHaus = document.createElement("p");
        noDataURLHaus.textContent = "No data available";
        urlHausDiv.appendChild(noDataURLHaus);
    }

    securityElement.appendChild(urlHausDiv);
}

async function load_ports(data, elementId) {
    const securityElement = document.getElementById(elementId);
    securityElement.innerHTML = '';  // Clear previous content

    // Check if data contains port_check_data
    if (data.port_check_data) {
        const { open_ports, failed_ports } = data.port_check_data;

        // Format open ports
        const openPortsDisplay = open_ports.join("\n");

        // Format failed ports
        const failedPortsDisplay = failed_ports.join(", ");

        // Construct the output
        const output = `Open Ports:
        ${openPortsDisplay}

        Unable to establish connections to:
        ${failedPortsDisplay}
        `;

        // Display the output in your desired HTML element
        const outputElement = document.getElementById("ports"); // Make sure you have an element with this ID
        outputElement.textContent = output; // Set the formatted output
    } else {
        console.error("No port check data found.");
    }
}

async function load_sitemap(data, elementId) {
    const sitemapElement = document.getElementById(elementId);
    sitemapElement.innerHTML = '';
    try {
        if (data.sitemap_data) {
            console.log("Sitemap Data:", data.sitemap_data);

            // Get the namespaces
            const namespaces = Object.keys(data.sitemap_data);
            console.log("Namespaces found:", namespaces);

            // Fetch sitemap entries from the first namespace
            const sitemapIndexNamespace = namespaces[0];
            const sitemapIndexArray = data.sitemap_data[sitemapIndexNamespace];

            console.log("Sitemap Index Array:", sitemapIndexArray);

            if (sitemapIndexArray && sitemapIndexArray.length > 0) {
                sitemapIndexArray.forEach(sitemapEntry => {
                    const sitemapKey = sitemapIndexNamespace.replace(
                        '{http://www.sitemaps.org/schemas/sitemap/0.9}', ''
                    ) + 'sitemap';

                    // Access the sitemap URLs
                    const sitemapArray = sitemapEntry[sitemapKey];

                    // Debug statement to inspect sitemapArray structure
                    console.log("Sitemap Array:", sitemapArray);

                    if (sitemapArray && sitemapArray.length > 0) {
                        sitemapArray.forEach(sitemap => {
                            // Access the 'loc' field correctly
                            const locKey = `${sitemapKey.replace('sitemap', 'loc')}`;
                            const loc = sitemap[locKey];

                            if (loc) {
                                // Create a link for each sitemap URL
                                const anchor = document.createElement("a");
                                anchor.href = loc;
                                anchor.target = "_blank";
                                anchor.innerText = loc;
                                sitemapElement.appendChild(anchor);
                                sitemapElement.appendChild(document.createElement("br")); // Line break
                            } else {
                                console.log("No 'loc' found in sitemap entry:", sitemap);
                            }
                        });
                    } else {
                        console.log("No sitemap URLs found in this entry:", sitemapEntry);
                    }
                });
            } else {
                sitemapElement.innerHTML = "<strong>No sitemaps found.</strong>";
            }
        } else {
            sitemapElement.innerHTML = "<strong>No sitemaps found.</strong>";
        }
    }
    catch (error) {
        console.error("Error fetching sitemap data:", error);
        document.getElementById("sitemaps").innerHTML = "<strong>Error loading sitemaps.</strong>";
    }
}

async function load_waf(data, elementId) {
    const wafElement = document.getElementById(elementId);
    wafElement.innerHTML = ''; // Clear previous content

    const hasWaf = data.waf_data.hasWaf;
    const statusMessage = hasWaf ? "✅ Yes" : "❌ No";

    wafElement.innerHTML = `Firewall: ${statusMessage}`;
}

async function load_metadata(data, elementId) {
    const metadataElement = document.getElementById(elementId);

    if (metadataElement && data && data.metadata) {
        const metadata = data.metadata;


        const metadataHTML = `<strong>Title:</strong> ${metadata.title || "N/A"}<br><br><strong>Description:</strong> ${metadata.description || "N/A"}<br><br><strong>Canonical URL:</strong> ${metadata.canonicalUrl || "N/A"}<br><br><strong>Keywords:</strong> ${metadata.keywords || "N/A"}<br><br><strong>Author:</strong> ${metadata.author || "N/A"}<br><br><strong>Googlebot:</strong> ${metadata.googlebot || "N/A"}<br><br><strong>Robots:</strong> ${metadata.robots || "N/A"}<br><br><strong>Favicon:</strong> ${metadata.favicon
            ? `<img src="${metadata.favicon}" alt="Favicon" style="width:16px;height:16px;"/>` : "N/A"
            }<br><br><strong>Open Graph Title:</strong> ${metadata.ogTitle || "N/A"}<br><br><strong>Open Graph Description:</strong> ${metadata.ogDescription || "N/A"}<br><br><strong>Twitter Site:</strong> ${metadata.twitterSite || "N/A"}<br>`;


        metadataElement.innerHTML = metadataHTML;
    } else {
        metadataElement.innerHTML = "<p>No metadata available.</p>";
    }
}

async function load_http_headers(data, elementId) {
    const headersElement = document.getElementById(elementId); // Ensure you have a container with this ID
    headersElement.innerHTML = `
        <p style="margin: 0;"><strong>Accept-Ranges:</strong> ${data.http_headers["Accept-Ranges"] || "N/A"
        }</p>
        <p style="margin: 0;"><strong>Cache-Control:</strong> ${data.http_headers["Cache-Control"] || "N/A"
        }</p>
        <p style="margin: 0;"><strong>Connection:</strong> ${data.http_headers["Connection"] || "N/A"
        }</p>
        <p style="margin: 0;"><strong>Content-Encoding:</strong> ${data.http_headers["Content-Encoding"] || "N/A"
        }</p>
        <p style="margin: 0;"><strong>Content-Length:</strong> ${data.http_headers["Content-Length"] || "N/A"
        }</p>
        <p style="margin: 0;"><strong>Content-Type:</strong> ${data.http_headers["Content-Type"] || "N/A"
        }</p>
        <p style="margin: 0;"><strong>Date:</strong> ${data.http_headers["Date"] || "N/A"
        }</p>
        <p style="margin: 0;"><strong>Server:</strong> ${data.http_headers["Server"] || "N/A"
        }</p>
        <p style="margin: 0;"><strong>Strict-Transport-Security:</strong> ${data.http_headers["Strict-Transport-Security"] || "N/A"
        }</p>
        <p style="margin: 0;"><strong>Vary:</strong> ${data.http_headers["Vary"] || "N/A"
        }</p>
        <p style="margin: 0;"><strong>cb-loc:</strong> ${data.http_headers["cb-loc"] || "N/A"
        }</p>
        <p style="margin: 0;"><strong>x-content-type-options:</strong> ${data.http_headers["x-content-type-options"] || "N/A"
        }</p>
        <p style="margin: 0;"><strong>x-frame-options:</strong> ${data.http_headers["x-frame-options"] || "N/A"
        }</p>
        <p style="margin: 0;"><strong>x-xss-protection:</strong> ${data.http_headers["x-xss-protection"] || "N/A"
        }</p>
    `
        .replace(/\s+/g, " ")
        .trim();
}

async function load_hsts(data, elementId) {
    const hstsElement = document.getElementById(elementId);
    // Ensure you have a container with this ID

    const hstsEnabled = data.hsts_data.compatible ? "✅ Yes" : "❌ No";


    const hstsHeader = data.hsts_data.hstsHeader || "N/A";
    const message = data.hsts_data.message || "N/A";


    const hstsOutput = `
        <p style="margin: 0;"><strong>HSTS Enabled?</strong> : ${hstsEnabled}</p>
        <p style="margin: 0;">${data.hsts_data.compatible ? "" : "Site does not serve any HSTS headers."
        }</p>
        <p style="margin: 0;"><strong>HSTS Header:</strong> ${hstsHeader}</p>
        <p style="margin: 0;"><strong>Message:</strong> ${message}</p>
    `;

    hstsElement.innerHTML = hstsOutput.replace(/\s+/g, " ").trim();
}

async function load_security_headers(data, elementId) {
    const headersElement = document.getElementById(elementId);
    headersElement.innerHTML = ''; // Clear previous content
    try {
        if (data.security_headers) {
            headersElement.innerHTML = `
                <p style="margin: 0;"><strong>Content Security Policy:</strong> ${data.security_headers.contentSecurityPolicy ? "✅ Yes" : "❌ No"
                }</p>
                <p style="margin: 0;"><strong>Strict Transport Policy:</strong> ${data.security_headers.strictTransportPolicy ? "✅ Yes" : "❌ No"
                }</p>
                <p style="margin: 0;"><strong>X-Content-Type-Options:</strong> ${data.security_headers.xContentTypeOptions ? "✅ Yes" : "❌ No"
                }</p>
                <p style="margin: 0;"><strong>X-Frame-Options:</strong> ${data.security_headers.xFrameOptions ? "✅ Yes" : "❌ No"
                }</p>
                <p style="margin: 0;"><strong>X-XSS-Protection:</strong> ${data.security_headers.xXSSProtection ? "✅ Yes" : "❌ No"
                }</p>
            `
                .replace(/\s+/g, " ")
                .trim();
        } else {
            headersElement.innerHTML = "<p>No HTTP security headers available.</p>";
        }
    } catch (error) {
        console.error("Error loading security headers:", error);
        const headersElement = document.getElementById("security-headers");
        headersElement.innerHTML = `<p>Error loading security headers: ${error.message}</p>`;
    }
}

async function load_domain_rank(data, elementId) {
    const rankElement = document.getElementById(elementId);
    rankElement.innerHTML = ''; // Clear previous content

    if (data.domain_rank && data.domain_rank.isFound) {
        rankElement.innerHTML = `
    <p style="margin: 0;"><strong>Domain:</strong> ${data.domain_rank.domain}</p>
    <p style="margin: 0;"><strong>Rank:</strong> ${data.domain_rank.rank}</p>
`
            .replace(/\s+/g, " ")
            .trim();
    } else {
        rankElement.innerHTML = '<p style="margin: 0;">Domain not found.</p>';
    }
}

async function load_link_analysis(data, elementId) {
    console.log(data); // Debugging log

    // Get the elements for displaying links
    const allDataElement = document.getElementById(elementId);

    // Initialize counts
    // let internalCount = 0;
    // let externalCount = 0;

    // Check if link_analysis exists in the response
    if (data.link_analysis) {
        const internalLinks = data.link_analysis.internal || [];
        const externalLinks = data.link_analysis.external || [];

        const internalLinkCount = internalLinks.length;
        const externalLinkCount = externalLinks.length;

        // Summary section
        const summaryHTML = `<strong>Summary</strong><br><br><strong>Internal Link Count:</strong> ${internalLinkCount}<br><strong>External Link Count:</strong> ${externalLinkCount}<br>
        `;

        // Internal Links dropdown
        const internalLinksHTML = internalLinkCount > 0
            ? `<details><summary><strong>Internal Links</strong></summary>${internalLinks.map(link => `<p>${link}</p>`).join("")}</details>`
            : `<details><summary><strong>Internal Links</strong></summary><p>No internal links found.</p></details>`;

        // External Links dropdown
        const externalLinksHTML = externalLinkCount > 0
            ? `<details><summary><strong>External Links</strong></summary>${externalLinks.map(link => `<p>${link}</p>`).join("")}</details>`
            : `<details><summary><strong>External Links</strong></summary><p>No external links found.</p></details>`;

        // Combine everything into the pre tag
        allDataElement.innerHTML = summaryHTML + internalLinksHTML + "<hr>" + externalLinksHTML;

    } else {
        // Handle case where no link analysis is available
        allDataElement.innerHTML = "<p>No link analysis available.</p>";
    }
}

async function load_mail_server_analysis(data, elementId) {
    // Get the element for displaying mail server analysis
    const mailServerElement = document.getElementById(elementId);

    // Check if mail_server_analysis exists in the response
    if (data.mail_server_analysis) {
        if (data.mail_server_analysis.skipped) {
            mailServerElement.innerHTML = `<p>${data.mail_server_analysis.skipped}</p>`;
        } else {
            mailServerElement.innerHTML =
                "<p>No mail server analysis available.</p>";
        }
    } else {
        mailServerElement.innerHTML = "<p>No mail server analysis available.</p>";
    }
}

async function load_ssl_certificate(data, elementId) {
    const sslCertElement = document.getElementById(elementId);

    if (sslCertElement && data && data.ssl_certificate) {
        const sslData = data.ssl_certificate;

        const ocspHTML = sslData.OCSP
            ? sslData.OCSP.map((link) => `<p>${link}</p>`).join("")
            : "<p>No OCSP links available.</p>";
        const caIssuersHTML = sslData.caIssuers
            ? sslData.caIssuers.map((link) => `<p>${link}</p>`).join("")
            : "<p>No CA Issuers available.</p>";
        const crlDistributionPointsHTML = sslData.crlDistributionPoints
            ? sslData.crlDistributionPoints.map((link) => `<p>${link}</p>`).join("")
            : "<p>No CRL Distribution Points available.</p>";

        const issuerHTML = sslData.issuer
            ? sslData.issuer.map((array) => `<p>${array[0][0]}: ${array[0][1]}</p>`).join("")
            : "<p>No issuer information available.</p>";
        const subjectHTML = sslData.subject
            ? sslData.subject.map((array) => `<p>${array[0][0]}: ${array[0][1]}</p>`).join("")
            : "<p>No subject information available.</p>";
        const subjectAltHTML = sslData.subjectAltName
            ? sslData.subjectAltName.map((array) => `<p>${array[0]}: ${array[1]}</p>`).join("")
            : "<p>No Subject Alternative Name available.</p>";

        sslCertElement.innerHTML = `<p><strong>Serial Number:</strong> ${sslData.serialNumber || "N/A"}</p><hr><p><strong>Not Before:</strong> ${sslData.notBefore || "N/A"}</p><hr><p><strong>Not After:</strong> ${sslData.notAfter || "N/A"}</p><hr><p><strong>Version:</strong> ${sslData.version || "N/A"}</p><hr><p><strong>Issuer:</strong> ${issuerHTML}</p><hr><p><strong>Subject:</strong> ${subjectHTML}</p><hr><p><strong>Subject Alternative Name:</strong> ${subjectAltHTML}</p><hr><p><strong>OCSP:</strong> ${ocspHTML}</p><hr><p><strong>CA Issuers:</strong> ${caIssuersHTML}</p><hr><p><strong>CRL Distribution Points:</strong> ${crlDistributionPointsHTML}</p>`;
    } else {
        sslCertElement.innerHTML = "<p>No SSL certificate data available.</p>";
    }
}

async function load_tranco_rank(data, elementId) {
    // Get the Tranco rank element
    const trancoElement = document.getElementById(elementId);

    // Check if tranco_rank exists in the response
    if (data.tranco_rank && data.tranco_rank.skipped) {
        trancoElement.innerHTML = `
    <p style="margin: 0;">${data.tranco_rank.skipped}</p>
`
            .replace(/\s+/g, " ")
            .trim();
    } else {
        trancoElement.innerHTML =
            '<p style="margin: 0;">Tranco rank not available.</p>';
    }
}

async function load_redirects(data, elementId) {
    const redirectsElement = document.getElementById(elementId);
    redirectsElement.innerHTML = ''; // Clear previous content

    if (data.redirects && data.redirects.redirects.length > 0) {

        redirectsElement.innerHTML = data.redirects.redirects
            .map((redirect) => `<p>${redirect}</p>`)
            .join("");
    } else {
        redirectsElement.innerHTML = "<p>No redirects found.</p>";
    }
}

function formatContact(contact) {
    contact = contact.trim();
    if (contact.includes("mailto:")) {
        const email = contact.replace("mailto:", "");
        return `<a class="link" href="mailto:${email}">mailto:${email}</a>`;
    }
    return `<a class="link" href="${contact}" target="_blank">${contact}</a>`;
}

function formatLink(url) {
    return url ? `<a href="${url}" class="link" target="_blank">${url}</a>` : "N/A";
}

async function load_security_txt(data, elementId) {
    const securityTxtElement = document.getElementById(elementId);
    securityTxtElement.innerHTML = "";
    if (data.security_txt_data && data.security_txt_data.isPresent) {
        const fields = data.security_txt_data.fields;
        if (fields) {
            Object.keys(fields).forEach((key) => {
                let value = fields[key];
                if (key === "Contact" && Array.isArray(value)) {
                    securityTxtElement.innerHTML += `<strong>${key}:</strong>`;
                    value.forEach((contact) => {
                        const formattedContact = formatContact(contact);
                        securityTxtElement.innerHTML += `<p style="margin-top: 0px; margin-bottom: 0px;">${formattedContact}</p>`;
                    });
                }
                else if (Array.isArray(value) && key !== "Contact") {
                    value = value.join(", ");
                    securityTxtElement.innerHTML += `<p><strong>${key}:</strong> ${value}</p>`;
                }
                else {
                    securityTxtElement.innerHTML += `<p><strong>${key}:</strong> ${formatLink(value)}</p>`;
                }
            });
        } else {
            securityTxtElement.innerHTML =
                "<p>No fields available in security.txt</p>";
        }
    } else {
        securityTxtElement.innerHTML = "<p>No security.txt file present</p>";
    }
}

async function load_robots_txt(data, elementId) {
    try {
        // Get the robots-txt element by its ID
        const robotsTxtElement = document.getElementById(elementId);
        robotsTxtElement.innerHTML = "";
        if (data.robots_txt_data && data.robots_txt_data.body) {
            console.log("Robots.txt data exists");
            const fields = data.robots_txt_data.body;

            if (Object.keys(fields).length === 0) {
                robotsTxtElement.innerHTML =
                    "<p>robots.txt file exists but it has no content.</p>";
            } else {
                Object.keys(fields).forEach((bot) => {
                    const botTitle = document.createElement("h4");
                    botTitle.innerText = `${bot}:`;
                    robotsTxtElement.appendChild(botTitle);

                    if (fields[bot].length === 0) {
                        const noRules = document.createElement("p");
                        noRules.innerText = "No rules defined for this bot.";
                        robotsTxtElement.appendChild(noRules);
                    } else {
                        fields[bot].forEach((rule) => {
                            const ruleElement = document.createElement("p");
                            ruleElement.innerHTML = `<strong>${rule.lbl}:</strong> ${rule.val}`;
                            robotsTxtElement.appendChild(ruleElement);
                        });
                    }
                });
            }
        } else {
            console.log("robots.txt file exists but has no content");
            robotsTxtElement.innerHTML =
                "<p>robots.txt file exists but it has no content.</p>";
        }
    } catch (error) {
        console.error("Error loading robots.txt data:", error);
        const robotsTxtElement = document.getElementById("robots-txt");
        if (error.message === "robots.txt file does not exist") {
            robotsTxtElement.innerHTML = `<p><strong>Error:</strong> robots.txt file does not exist on this server.</p>`;
        } else {
            robotsTxtElement.innerHTML = `<p><strong>Error:</strong> Failed to load robots.txt data. Please try again later.</p>`;
        }
    }
}

async function load_screenshot(data, elementId) {
    const screenshotElement = document.getElementById(elementId);
    screenshotElement.innerHTML = ""; // Clear previous content

    if (data.screenshot_data) {
        screenshotElement.innerHTML = `<img src="${data.screenshot_data}" alt="Screenshot" style="max-width: 100%; height: auto;"/>`;
    } else {
        screenshotElement.innerHTML = "<p>No screenshot data available</p>";
    }
}

function displayServerInfo(data, elementId) {
    document.getElementById(elementId).innerHTML = `<p><strong>City:</strong> ${data.city}, ${data.regionName}</p><p><strong>Country:</strong> ${data.country} (${data.countryCode})</p><p><strong>Timezone:</strong> ${data.timezone}</p><p><strong>Latitude:</strong> ${data.lat}</p><p><strong>Longitude:</strong> ${data.lon}</p><p><strong>ISP:</strong> ${data.isp}</p>`;
}

let map;
function showMap(lat, lon, city, country) {
    const mapContainer = document.getElementById('map');

    if (mapContainer) {
        mapContainer.remove();
        const newMapContainer = document.createElement('div');
        newMapContainer.id = 'map';
        newMapContainer.style.height = '400px';
        newMapContainer.style.width = '100%';
        document.querySelector('.server_location').appendChild(newMapContainer);
    }

    map = L.map('map').setView([lat, lon], 13);

    L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
        attribution: 'Map data © <a href="https://openstreetmap.org">OpenStreetMap</a> contributors',
    }).addTo(map);

    L.marker([lat, lon]).addTo(map)
        .bindPopup(`<b>Server Location</b><br>${city}, ${country}`)
        .openPopup();
}

async function load_server_location(data, elementId, section) {
    try {
        if (data.server_location.status === 'fail') {
            document.getElementById(elementId).innerHTML = `<p>Error: ${data.server_location.message}</p>`;
            return;
        }

        displayServerInfo(data.server_location, elementId);

        const { lat, lon, city, country } = data.server_location;
        if (lat === undefined || lon === undefined) {
            throw new Error("Latitude or Longitude is undefined");
        }

        showMap(lat, lon, city, country);
    } catch (error) {
        document.getElementById(elementId).innerHTML = `<p>Error fetching server location.</p>`;
    }
}
document.addEventListener("DOMContentLoaded", function () {
    const urlForm = document.getElementById("url-form");
    if (urlForm) {
        urlForm.addEventListener("submit", async function (event) {
            event.preventDefault();
            const urlInput = document.getElementById("url_or_ip").value;
            await load_server_location(urlInput);
        });
    } else {
        console.error("Form element with id 'url-form' not found.");
    }
});

async function load_tls_handshake_simulation(data, elementId) {
    // Get the TLS handshake results element by its ID
    const tlsResultsElement = document.getElementById(elementId);

    // Clear previous content
    tlsResultsElement.innerHTML = "";

    // Check if TLS handshake data is present
    if (data.tls_handshake && Array.isArray(data.tls_handshake)) {
        const tlsHandshakeHTML = data.tls_handshake
            .map((result) => {
                return `<details>
                <summary>${result.user_agent}</summary>
                <div><strong>Protocol:</strong> ${result.protocol}<br><strong>Cipher Suite:</strong> ${result.cipher_suite} (Code: ${result.cipher_suite_code})<br><strong>Curve:</strong> ${result.curve} (Code: ${result.curve_code})<br><strong>OCSP Stapling:</strong> ${result.ocsp_stapling ? "Yes" : "No"}<br><strong>PFS:</strong> ${result.pfs || "N/A"}<br><strong>Public Key:</strong> ${result.pubkey} bits<br><strong>Signature Algorithm:</strong> ${result.sigalg || "N/A"}<br><strong>Ticket Hint:</strong> ${result.ticket_hint || "N/A"}
                </div> </details><hr>`;
            })
            .join("");

        tlsResultsElement.innerHTML = tlsHandshakeHTML;
    } else {
        tlsResultsElement.innerHTML = "<p>No TLS handshake data available.</p>";
    }
}

async function load_tls_security(data, elementId) {
    const tlsSecurityConfigElement = document.getElementById(elementId);
    // Clear previous content
    tlsSecurityConfigElement.innerHTML = "";

    const tlsBody = data.tls_security?.body;

    if (tlsBody && Array.isArray(tlsBody) && tlsBody.length > 0) {
        tlsBody.forEach((item) => {
            // Create a details element for each analyzer
            const detailsElement = document.createElement("details");

            // Create a summary element
            const summaryElement = document.createElement("summary");
            summaryElement.innerHTML = `${item.analyzer} (ID: ${item.id})`;
            detailsElement.appendChild(summaryElement);

            // Create a content div for the detailed information
            const contentDiv = document.createElement("div");

            if (item.result) {
                if (typeof item.result === 'object' && !Array.isArray(item.result)) {
                    if (item.result.has_caa !== undefined) {
                        contentDiv.innerHTML += `<p><strong>Has CAA:</strong> ${item.result.has_caa ? "Yes" : "No"}</p>`;
                    }
                    contentDiv.innerHTML += `<p><strong>Host:</strong> ${item.result.host || "N/A"}</p>`;
                    contentDiv.innerHTML += `<p><strong>Issue:</strong> ${item.result.issue || "N/A"}</p>`;
                    contentDiv.innerHTML += `<p><strong>Wildcard Issue:</strong> ${item.result.issuewild || "N/A"}</p>`;
                } else if (Array.isArray(item.result)) {
                    contentDiv.innerHTML += `<p><strong>SSL Labs Results:</strong></p>`;
                    item.result.forEach((resultItem, index) => {
                        contentDiv.innerHTML += `<p>Result ${index + 1}: ${JSON.stringify(resultItem)}</p>`;
                    });
                } else {
                    contentDiv.innerHTML += `<p>No detailed result data available.</p>`;
                }
            } else {
                contentDiv.innerHTML += `<p>No result data available for this analyzer.</p>`;
            }

            // Append the content div to the details element
            detailsElement.appendChild(contentDiv);
            // Append the details element to the main container
            tlsSecurityConfigElement.appendChild(detailsElement);

            // Add a line break (horizontal rule) after each analyzer
            tlsSecurityConfigElement.appendChild(document.createElement("hr"));
        });
    } else {
        tlsSecurityConfigElement.innerHTML = "<p>No TLS security configuration data available.</p>";
    }
}

async function load_tls_cipher(data, elementId) {
    const tlsCipherSuitesElement = document.getElementById(elementId);

    // Clear previous content
    tlsCipherSuitesElement.innerHTML = "";

    // Access the body from tls_cipher
    const cipherSuitesBody = data.tls_cipher?.body?.cipher_suites;

    if (cipherSuitesBody && Array.isArray(cipherSuitesBody) && cipherSuitesBody.length > 0) {
        cipherSuitesBody.forEach((item) => {
            // Create a details element for each cipher suite
            const detailsElement = document.createElement("details");

            // Create a summary element
            const summaryElement = document.createElement("summary");
            // Access the cipher property directly from the item
            summaryElement.innerHTML = `${item.cipher}`; // Adjust success status as needed
            detailsElement.appendChild(summaryElement);

            // Create a content div for the detailed information
            const contentDiv = document.createElement("div");

            // Check for details in the item
            if (item) {
                contentDiv.innerHTML += `<p><strong>Curves:</strong> ${item.curves ? item.curves.join(', ') : 'N/A'}</p>`;
                contentDiv.innerHTML += `<p><strong>OCSP Stapling:</strong> ${item.ocsp_stapling ? 'Yes' : 'No'}</p>`;
                contentDiv.innerHTML += `<p><strong>PFS:</strong> ${item.pfs || 'N/A'}</p>`;
                contentDiv.innerHTML += `<p><strong>Protocols:</strong> ${item.protocols ? item.protocols.join(', ') : 'N/A'}</p>`;
            } else {
                contentDiv.innerHTML += `<p>No detailed result data available.</p>`;
            }

            // Append the content div to the details element
            detailsElement.appendChild(contentDiv);
            // Append the details element to the main container
            tlsCipherSuitesElement.appendChild(detailsElement);

            // Add a line break (horizontal rule) after each cipher suite
            tlsCipherSuitesElement.appendChild(document.createElement("hr"));
        });
    } else {
        tlsCipherSuitesElement.innerHTML = "<p>No TLS cipher suite data available.</p>";
    }
}

async function load_score_metrics(data, elementId) {


    console.log("Raw data: ", data); // Log the entire response for inspection

    accumulatedData.push(data.metrics_data); // Storing the fetched metrics in accumulatedData
    console.log("Score Metrics: ", data);

    const scoreElement = document.getElementById(elementId);
    scoreElement.innerHTML = "";

    // Check for score and explanations
    if (data.score !== undefined) { // Check if score is present
        scoreElement.innerHTML = `<p><strong>Score:</strong> ${data.score}</p><p><strong>Explanations:</strong></p><ul>${data.explanations.map(item => `<li><strong>${item.explanation}</strong><br><em>Risk:</em> ${item.risk}<br><em>Suggestion:</em> ${item.suggestion}</li>`).join('')}</ul>`;
    } else {
        scoreElement.innerHTML = "<p>No score data available</p>";
    }
}