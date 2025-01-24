let accumulatedData = [];

document.addEventListener("DOMContentLoaded", function () {
    const urlOrIp = document.getElementById("domainName").innerText;
    function capitalizeFirstLetter(string) {
        return string.charAt(0).toUpperCase() + string.slice(1);
    }

    async function Load_whois() {
        const response = await fetch("/fetch_whois_data", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify({ url_or_ip: urlOrIp }),
        });

        const data = await response.json();
        accumulatedData.push(data.whois_data);
        console.log("1: ", data);
        const whois = document.getElementById("whois");
        whois.innerHTML = ""; // Clear previous content

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
    Load_whois();

    async function load_dns_data() {
        const response = await fetch("/fetch_dns_data", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify({ url_or_ip: urlOrIp }),
        });

        const data = await response.json();
        accumulatedData.push(data.dns_data);
        console.log("2: ", data);
        const dnsElement = document.getElementById("dns");
        dnsElement.innerHTML = "";

        dnsElement.innerHTML = `<div id="dns_data"><strong>IP Address:</strong><div>${data.dns_data.ip}</div></div>`;
    }
    load_dns_data();

    async function load_dns_records() {
        const response = await fetch("/fetch_dns_records", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify({ url_or_ip: urlOrIp }),
        });

        const data = await response.json();
        accumulatedData.push(data.dns_records_data);
        console.log("3: ", data);
        const dnsElement = document.getElementById("dns-records");
        dnsElement.innerHTML = "";

        // Create a container for DNS records data
        const recordsContainer = document.createElement("div");
        recordsContainer.setAttribute("id", "dns_records_data");

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
    load_dns_records();

    async function load_dnssec() {
        const response = await fetch("/fetch_dnssec", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify({ url_or_ip: urlOrIp }),
        });

        const data = await response.json();
        accumulatedData.push(data.dnssec_data);
        console.log("4: ", data);
        const dnsElement = document.getElementById("dnssec");
        dnsElement.innerHTML = "";

        // Create a container for DNSSEC data
        const dnssecDataContainer = document.createElement("div");
        dnssecDataContainer.setAttribute("id", "dnssec_data");

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
    load_dnssec();

    async function load_wayback() {
        const response = await fetch("/fetch_wayback", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify({ url_or_ip: urlOrIp }),
        });

        const data = await response.json();
        accumulatedData.push(data.wayback_data);
        console.log("5: ", data);
        const waybackElement = document.getElementById("wayback");
        waybackElement.innerHTML = "";

        // Create a container for Wayback data
        const waybackDataContainer = document.createElement("div");
        waybackDataContainer.setAttribute("id", "wayback_data");

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
    load_wayback();

    async function load_carbon_footprint() {
        const response = await fetch("/fetch_carbon_footprint", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify({ url_or_ip: urlOrIp }),
        });

        const data = await response.json();
        accumulatedData.push(data.carbon_footprint_data);
        console.log("6: ", data);
        const carbonFootprintElement = document.getElementById("carbon");
        carbonFootprintElement.innerHTML = ""; // Clear previous content

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
    load_carbon_footprint();

    async function load_status() {
        const response = await fetch("/fetch_status", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify({ url_or_ip: urlOrIp }),
        });

        const data = await response.json();
        accumulatedData.push(data.status_data);
        console.log("7: ", data);
        const statusElement = document.getElementById("status");
        statusElement.innerHTML = ""; // Clear previous content

        // Check if status_data exists
        if (data && data.status_data) {
            const statusData = data.status_data;

            // Create HTML content in the desired format
            statusElement.innerHTML = `<div><strong>Is Up?</strong> : ${statusData.isUp ? "✅ Online" : "❌ Offline"
                }<br><br><strong>Status Code</strong> : ${statusData.responseCode || "No data available"
                }<br><br><strong>Response Time</strong> : ${statusData.responseTime
                    ? `${statusData.responseTime} ms`
                    : "No data available"
                }</div>`;
        } else {
            statusElement.innerHTML = "No status data available";
        }
    }
    load_status();

    async function load_traceroute() {
        const response = await fetch("/fetch_traceroute", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify({ url_or_ip: urlOrIp }),
        });

        const data = await response.json();
        accumulatedData.push(data.traceroute_data);
        console.log("8: ", data); // Check the structure of the data received

        // Get the traceroute element by its ID
        const tracerouteElement = document.getElementById("traceroute");

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
                            : ""
                        }
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
    }
    load_traceroute();

    async function load_blocklist() {
        const response = await fetch("/fetch_blocklist", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify({ url_or_ip: urlOrIp }),
        });

        const data = await response.json();
        accumulatedData.push(data.blocklist_results);
        console.log("9: ", data);

        const blocklistElement = document.getElementById("blocklist");

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
    load_blocklist();

    async function load_threats() {
        const response = await fetch("/fetch_threats", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify({ url_or_ip: urlOrIp }),
        });

        const data = await response.json();
        accumulatedData.push(data.threats_data);
        console.log("10: ", data); // Log the full response to check the structure
        const securityElement = document.getElementById("threats");
        securityElement.innerHTML = ""; // Clear previous content

        // PhishTank Section (Phishing Status)
        const phishTankDiv = document.createElement("div");
        const phishTankTitle = document.createElement("h3");
        phishTankTitle.textContent = "Phishing Status";
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
    load_threats();

    async function load_port_check() {
        const response = await fetch("/fetch_port_check", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify({ url_or_ip: urlOrIp }),
        });

        const data = await response.json();
        accumulatedData.push(data.port_check_data);
        console.log("11: ", data);

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
    load_port_check();

    async function load_sitemap() {
        try {
            const response = await fetch("/fetch_sitemap", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                },
                body: JSON.stringify({ url_or_ip: urlOrIp }),
            });

            const data = await response.json();
            accumulatedData.push(data.sitemap_data);
            console.log("12: ", data);

            const sitemapElement = document.getElementById("sitemaps");
            sitemapElement.innerHTML = ""; // Clear previous content

            // Recursively search for 'loc' or any other relevant URL fields
            function extractUrls(obj) {
                let urls = [];
                if (typeof obj === "object" && obj !== null) {
                    for (const key in obj) {
                        if (obj.hasOwnProperty(key)) {
                            if (key.includes("loc") && typeof obj[key] === "string") {
                                // If a 'loc' field is found, treat it as a URL
                                urls.push(obj[key]);
                            } else if (typeof obj[key] === "object") {
                                // Recurse through nested objects
                                urls = urls.concat(extractUrls(obj[key]));
                            }
                        }
                    }
                }
                return urls;
            }

            // Check if 'sitemap_data' exists in the response
            if (data.sitemap_data) {
                const namespaces = Object.keys(data.sitemap_data);
                console.log("Namespaces found:", namespaces);

                // Iterate through all namespaces to collect sitemap URLs
                namespaces.forEach((namespace) => {
                    const sitemapEntries = data.sitemap_data[namespace];
                    if (Array.isArray(sitemapEntries)) {
                        sitemapEntries.forEach((entry) => {
                            const urls = extractUrls(entry);
                            if (urls.length > 0) {
                                urls.forEach((url) => {
                                    // Create a link for each extracted URL
                                    const anchor = document.createElement("a");
                                    anchor.setAttribute("class", "link-color");
                                    anchor.href = url;
                                    anchor.target = "_blank";
                                    anchor.innerText = url;
                                    sitemapElement.appendChild(anchor);
                                    sitemapElement.appendChild(document.createElement("hr"));
                                    sitemapElement.appendChild(document.createElement("br")); // Line break
                                });
                            } else {
                                console.log("No URLs found in this sitemap entry:", entry);
                            }
                        });
                    }
                });
            } else {
                sitemapElement.innerHTML = "<strong>No sitemaps found.</strong>";
            }
        } catch (error) {
            console.error("Error fetching sitemap data:", error);
            document.getElementById("sitemaps").innerHTML =
                "<strong>Error loading sitemaps.</strong>";
        }
    }
    load_sitemap();

    async function load_waf() {
        const response = await fetch("/fetch_waf", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify({ url_or_ip: urlOrIp }),
        });

        const data = await response.json();
        accumulatedData.push(data.waf_data);
        console.log("13: ", data);

        const wafElement = document.getElementById("waf");
        wafElement.innerHTML = "";

        const hasWaf = data.waf_data.hasWaf;
        const statusMessage = hasWaf ? "✅ Yes" : "❌ No";

        wafElement.innerHTML = `Firewall: ${statusMessage}`;
    }
    load_waf();

    async function load_metadata() {
        const response = await fetch("/fetch_metadata", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify({ url_or_ip: urlOrIp }),
        });

        const data = await response.json();
        accumulatedData.push(data.metadata);
        console.log("14: ", data);

        const metadataElement = document.getElementById("metadata");

        if (metadataElement && data && data.metadata) {
            const metadata = data.metadata;

            const metadataHTML = `<strong>Title:</strong> ${metadata.title || "N/A"
                }<br/>
				<strong>Description:</strong> ${metadata.description || "N/A"}<br/>
				<strong>Canonical URL:</strong> ${metadata.canonicalUrl || "N/A"}<br/>
				<strong>Keywords:</strong> ${metadata.keywords || "N/A"}<br/>
				<strong>Author:</strong> ${metadata.author || "N/A"}<br/>
				<strong>Googlebot:</strong> ${metadata.googlebot || "N/A"}<br/>
				<strong>Robots:</strong> ${metadata.robots || "N/A"}<br/>
				<strong>Favicon:</strong> ${metadata.favicon
                    ? `<img src="${metadata.favicon}" alt="Favicon" style="width:16px;height:16px;"/>`
                    : "N/A"
                }<br/>
				<strong>Open Graph Title:</strong> ${metadata.ogTitle || "N/A"}<br/>
				<strong>Open Graph Description:</strong> ${metadata.ogDescription || "N/A"}<br/>
				<strong>Twitter Site:</strong> ${metadata.twitterSite || "N/A"}<br/>`;

            metadataElement.innerHTML = metadataHTML;
        } else {
            metadataElement.innerHTML = "<p>No metadata available.</p>";
        }
    }
    load_metadata();

    async function load_http_headers() {
        const response = await fetch("/fetch_http_headers", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify({ url_or_ip: urlOrIp }),
        });

        const data = await response.json();
        accumulatedData.push(data.http_headers);
        console.log("15: ", data);

        const headersElement = document.getElementById("http-headers");
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
    load_http_headers();

    async function load_hsts() {
        const response = await fetch("/fetch_hsts", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify({ url_or_ip: urlOrIp }),
        });

        const data = await response.json();
        accumulatedData.push(data.hsts_data);
        console.log("16: ", data);

        const hstsElement = document.getElementById("hsts");
        hstsElement.innerHTML = "";

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
    load_hsts();

    async function load_security_headers() {
        try {
            const response = await fetch("/fetch_security_headers", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                },
                body: JSON.stringify({ url_or_ip: urlOrIp }),
            });

            if (!response.ok) {
                throw new Error(`HTTP error! Status: ${response.status}`);
            }

            const data = await response.json();
            accumulatedData.push(data.security_headers);
            console.log("17: ", data);

            const headersElement = document.getElementById("security-headers");

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
    load_security_headers();

    async function load_domain_rank() {
        const response = await fetch("/fetch_domain_rank", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify({ url_or_ip: urlOrIp }),
        });

        const data = await response.json();
        accumulatedData.push(data.domain_rank);
        console.log("18: ", data);

        const rankElement = document.getElementById("domain-rank");

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
    load_domain_rank();

    async function load_link_analysis() {
        const response = await fetch("/fetch_link_analysis", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify({ url_or_ip: urlOrIp }),
        });

        const data = await response.json();
        accumulatedData.push(data.link_analysis);
        console.log("19: ", data);

        const allDataElement = document.getElementById("all-data");

        if (data.link_analysis) {
            const internalLinks = data.link_analysis.internal || [];
            const externalLinks = data.link_analysis.external || [];

            const internalLinkCount = internalLinks.length;
            const externalLinkCount = externalLinks.length;

            // Summary section
            const summaryHTML = `<strong>Summary</strong><br><br><strong>Internal Link Count:</strong> ${internalLinkCount}<br><strong>External Link Count:</strong> ${externalLinkCount}<br>
            `;

            // Internal Links dropdown
            const internalLinksHTML =
                internalLinkCount > 0
                    ? `<details><summary><strong>Internal Links</strong></summary>${internalLinks
                        .map(
                            (link) =>
                                `<a target="_blank" class="link-color" href="${link}">${link}</a><hr>`
                        )
                        .join("")}</details>`
                    : `<details><summary><strong>Internal Links</strong></summary><p>No internal links found.</p></details>`;

            // External Links dropdown
            const externalLinksHTML =
                externalLinkCount > 0
                    ? `<details><summary><strong>External Links</strong></summary>${externalLinks
                        .map(
                            (link) =>
                                `<a target="_blank" class="link-color" href="${link}">${link}</a><hr>`
                        )
                        .join("")}</details>`
                    : `<details><summary><strong>External Links</strong></summary><p>No external links found.</p></details>`;

            // Combine everything into the pre tag
            allDataElement.innerHTML =
                summaryHTML + internalLinksHTML + "<hr>" + externalLinksHTML;
        } else {
            // Handle case where no link analysis is available
            allDataElement.innerHTML = "<p>No link analysis available.</p>";
        }
    }
    load_link_analysis();

    async function load_mail_server_analysis() {
        const response = await fetch("/fetch_mail_server_analysis", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify({ url_or_ip: urlOrIp }),
        });

        const data = await response.json();
        accumulatedData.push(data.mail_server_analysis);
        console.log("20: ", data);

        const mailServerElement = document.getElementById("mail-services");

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
    load_mail_server_analysis();

    async function load_ssl_certificate() {
        const response = await fetch("/fetch_ssl_certificate", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify({ url_or_ip: urlOrIp }),
        });

        const data = await response.json();
        accumulatedData.push(data.ssl_certificate);
        console.log("21: ", data);

        const sslCertElement = document.getElementById("ssl");

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
                ? sslData.issuer
                    .map((array) => `<p>${array[0][0]}: ${array[0][1]}</p>`)
                    .join("")
                : "<p>No issuer information available.</p>";
            const subjectHTML = sslData.subject
                ? sslData.subject
                    .map((array) => `<p>${array[0][0]}: ${array[0][1]}</p>`)
                    .join("")
                : "<p>No subject information available.</p>";
            const subjectAltHTML = sslData.subjectAltName
                ? sslData.subjectAltName
                    .map((array) => `<p>${array[0]}: ${array[1]}</p>`)
                    .join("")
                : "<p>No Subject Alternative Name available.</p>";

            sslCertElement.innerHTML = `<p><strong>Serial Number:</strong> ${sslData.serialNumber || "N/A"
                }</p><hr><p><strong>Not Before:</strong> ${sslData.notBefore || "N/A"
                }</p><hr><p><strong>Not After:</strong> ${sslData.notAfter || "N/A"
                }</p><hr><p><strong>Version:</strong> ${sslData.version || "N/A"
                }</p><hr><p><strong>Issuer:</strong> ${issuerHTML}</p><hr><p><strong>Subject:</strong> ${subjectHTML}</p><hr><p><strong>Subject Alternative Name:</strong> ${subjectAltHTML}</p><hr><p><strong>OCSP:</strong> ${ocspHTML}</p><hr><p><strong>CA Issuers:</strong> ${caIssuersHTML}</p><hr><p><strong>CRL Distribution Points:</strong> ${crlDistributionPointsHTML}</p>`;
        } else {
            sslCertElement.innerHTML = "<p>No SSL certificate data available.</p>";
        }
    }
    load_ssl_certificate();

    async function load_tranco_rank() {
        const response = await fetch("/fetch_tranco_rank", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify({ url_or_ip: urlOrIp }),
        });

        const data = await response.json();
        accumulatedData.push(data.tranco_rank);
        console.log("22: ", data);

        const trancoElement = document.getElementById("tranco-rank");

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
    load_tranco_rank();

    async function load_redirects() {
        const response = await fetch("/fetch_redirects", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify({ url_or_ip: urlOrIp }),
        });

        const data = await response.json();
        accumulatedData.push(data.redirects);
        console.log("23: ", data);

        const redirectsElement = document.getElementById("redirects");

        if (data.redirects && data.redirects.redirects.length > 0) {
            redirectsElement.innerHTML = data.redirects.redirects
                .map((redirect) => `<p>${redirect}</p>`)
                .join("");
        } else {
            redirectsElement.innerHTML = "<p>No redirects found.</p>";
        }
    }
    load_redirects();

    function formatContact(contact) {
        contact = contact.trim(); // Clean up spaces
        if (contact.includes("mailto:")) {
            const email = contact.replace("mailto:", "");
            return `<a class="link" href="mailto:${email}">mailto:${email}</a>`;
        }
        return `<a class="link" href="${contact}" target="_blank">${contact}</a>`;
    }

    function formatLink(url) {
        return url
            ? `<a target="_blank" class="link" href="${url}">${url}</a>`
            : "N/A";
    }

    async function load_security_txt() {
        const response = await fetch("/fetch_security_txt", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify({ url_or_ip: urlOrIp }),
        });

        const data = await response.json();
        accumulatedData.push(data.security_txt_data);
        console.log("24: ", data);

        const securityTxtElement = document.getElementById("security-txt");

        securityTxtElement.innerHTML = ""; // Clear previous content

        if (data.security_txt_data && data.security_txt_data.isPresent) {
            const fields = data.security_txt_data.fields;

            if (fields) {
                Object.keys(fields).forEach((key) => {
                    let value = fields[key];

                    // Special handling for "Contact" field with multiple values
                    if (key === "Contact" && Array.isArray(value)) {
                        securityTxtElement.innerHTML += `<strong>${key}:</strong>`;
                        value.forEach((contact) => {
                            const formattedContact = formatContact(contact);
                            securityTxtElement.innerHTML += `<p style="margin-top: 0px; margin-bottom: 0px;">${formattedContact}</p>`;
                        });
                    }
                    else if (Array.isArray(value) && key !== "Contact") {
                        // If the value is an array for any other key, join the values
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
    load_security_txt();

    async function load_robots_txt() {
        try {
            const response = await fetch("/fetch_robots_txt", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                },
                body: JSON.stringify({ url_or_ip: urlOrIp }),
            });

            // Check if the file exists (non-404 response)
            if (response.status === 404) {
                throw new Error("robots.txt file does not exist");
            }

            const data = await response.json();
            console.log("25: ", data);
            const robotsTxtElement = document.getElementById("robots-txt");
            robotsTxtElement.innerHTML = ""; // Clear previous content

            // Check if robots.txt data exists and has content
            if (data.robots_txt_data && data.robots_txt_data.body) {
                console.log("Robots.txt data exists");
                const fields = data.robots_txt_data.body;

                if (Object.keys(fields).length === 0) {
                    // If the file exists but is empty
                    robotsTxtElement.innerHTML =
                        "<p>robots.txt file exists but it has no content.</p>";
                } else {
                    // If the file has content, display it
                    Object.keys(fields).forEach((bot) => {
                        // Display bot name
                        const botTitle = document.createElement("h4");
                        botTitle.innerText = `${bot}:`;
                        robotsTxtElement.appendChild(botTitle);

                        if (fields[bot].length === 0) {
                            const noRules = document.createElement("p");
                            noRules.innerText = "No rules defined for this bot.";
                            robotsTxtElement.appendChild(noRules);
                        } else {
                            // Loop through each rule and display it
                            fields[bot].forEach((rule) => {
                                const ruleElement = document.createElement("p");
                                ruleElement.innerHTML = `<strong>${rule.lbl}:</strong> ${rule.val}`;
                                robotsTxtElement.appendChild(ruleElement);
                            });
                        }
                    });
                }
            } else {
                // If the file exists but has no body/content
                console.log("robots.txt file exists but has no content");
                robotsTxtElement.innerHTML =
                    "<p>robots.txt file exists but it has no content.</p>";
            }
        } catch (error) {
            // Handle cases where the file doesn't exist or other errors
            console.error("Error loading robots.txt data:", error);
            const robotsTxtElement = document.getElementById("robots-txt");
            if (error.message === "robots.txt file does not exist") {
                robotsTxtElement.innerHTML = `<p><strong>Error:</strong> robots.txt file does not exist on this server.</p>`;
            } else {
                robotsTxtElement.innerHTML = `<p><strong>Error:</strong> Failed to load robots.txt data. Please try again later.</p>`;
            }
        }
    }
    load_robots_txt();

    async function load_screenshot() {
        const response = await fetch("/fetch_screenshot", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify({ url_or_ip: urlOrIp }),
        });

        const data = await response.json();
        accumulatedData.push(data.dns_data);
        console.log("26: ", data);

        const screenshotElement = document.getElementById("screenshot");
        screenshotElement.innerHTML = "";

        if (data.screenshot_data) {
            screenshotElement.innerHTML = `<img src="${data.screenshot_data}" alt="Screenshot" style="max-width: 100%; height: auto;"/>`;
        } else {
            screenshotElement.innerHTML = "<p>No screenshot data available</p>";
        }
    }
    load_screenshot();

    async function load_server_location(urlOrIp) {
        try {
            console.log("this is our url: ", urlOrIp);
            const response = await fetch("/fetch_server_location", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                },
                body: JSON.stringify({ url_or_ip: urlOrIp }),
            });

            const data = await response.json();
            accumulatedData.push(data.server_location);
            console.log("27: ", data);

            if (data.server_location.status === "fail") {
                document.getElementById("server-info").innerHTML = `<p>Error: ${data.server_location.message}</p>`;
                return;
            }

            displayServerInfo(data.server_location);

            const { lat, lon, city, country } = data.server_location;
            console.log(`Latitude: ${lat}, Longitude: ${lon}`);
            if (lat === undefined || lon === undefined) {
                throw new Error("Latitude or Longitude is undefined");
            }

            showMap(lat, lon, city, country);
        } catch (error) {
            console.error("Error fetching server location:", error);
            document.getElementById(
                "server-info"
            ).innerHTML = `<p>Error fetching server location.</p>`;
        }
    }

    function displayServerInfo(data) {
        document.getElementById(
            "server-info"
        ).innerHTML = `<p><strong>City:</strong> ${data.city}, ${data.regionName}</p><p><strong>Country:</strong> ${data.country} (${data.countryCode})</p><p><strong>Timezone:</strong> ${data.timezone}</p><p><strong>Latitude:</strong> ${data.lat}</p><p><strong>Longitude:</strong> ${data.lon}</p><p><strong>ISP:</strong> ${data.isp}</p>`;
    }

    let map;
    function showMap(lat, lon, city, country) {
        const mapContainer = document.getElementById('map');
        if (map !== undefined) {
            map.remove(); // Remove the previous map instance if it exists
        }
        else if (mapContainer._leaflet_id) {
            // If _leaflet_id exists on the map container, it means it's already initialized, so reset it
            mapContainer.innerHTML = ""; // Clear previous map content
        }
    
        // Initialize a new map
        map = L.map('map').setView([lat, lon], 13);
    
        L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
            attribution: 'Map data © <a href="https://openstreetmap.org">OpenStreetMap</a> contributors',
        }).addTo(map);
    
        L.marker([lat, lon]).addTo(map)
            .bindPopup(`<b>Server Location</b><br>${city}, ${country}`)
            .openPopup();
    
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
    load_server_location(urlOrIp);

    async function load_tls_handshake_simulation() {
        const response = await fetch("/fetch_tls_handshake", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify({ url_or_ip: urlOrIp }),
        });

        const data = await response.json();
        accumulatedData.push(data.tls_handshake);
        console.log("28: ", data);

        const tlsResultsElement = document.getElementById("tls-handshake-results");

        tlsResultsElement.innerHTML = "";

        if (data.tls_handshake && Array.isArray(data.tls_handshake)) {
            const tlsHandshakeHTML = data.tls_handshake
                .map((result) => {
                    return `<details>
                  <summary>${result.user_agent}</summary>
                  <div><strong>Protocol:</strong> ${result.protocol
                        }<br><strong>Cipher Suite:</strong> ${result.cipher_suite
                        } (Code: ${result.cipher_suite_code})<br><strong>Curve:</strong> ${result.curve
                        } (Code: ${result.curve_code})<br><strong>OCSP Stapling:</strong> ${result.ocsp_stapling ? "Yes" : "No"
                        }<br><strong>PFS:</strong> ${result.pfs || "N/A"
                        }<br><strong>Public Key:</strong> ${result.pubkey
                        } bits<br><strong>Signature Algorithm:</strong> ${result.sigalg || "N/A"
                        }<br><strong>Ticket Hint:</strong> ${result.ticket_hint || "N/A"}
                  </div> </details><hr>`;
                })
                .join("");

            tlsResultsElement.innerHTML = tlsHandshakeHTML;
        } else {
            tlsResultsElement.innerHTML = "<p>No TLS handshake data available.</p>";
        }
    }
    load_tls_handshake_simulation();

    async function load_tls_security() {
        const response = await fetch("/fetch_tls_security", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify({ url_or_ip: urlOrIp }),
        });

        const data = await response.json();
        accumulatedData.push(data.tls_security);
        console.log("29: ", data);

        const tlsSecurityConfigElement = document.getElementById("tls-security");

        // Clear previous content
        tlsSecurityConfigElement.innerHTML = "";

        // Access the body from tls_security
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
                    if (typeof item.result === "object" && !Array.isArray(item.result)) {
                        if (item.result.has_caa !== undefined) {
                            contentDiv.innerHTML += `<p><strong>Has CAA:</strong> ${item.result.has_caa ? "Yes" : "No"
                                }</p>`;
                        }
                        contentDiv.innerHTML += `<p><strong>Host:</strong> ${item.result.host || "N/A"
                            }</p>`;
                        contentDiv.innerHTML += `<p><strong>Issue:</strong> ${item.result.issue || "N/A"
                            }</p>`;
                        contentDiv.innerHTML += `<p><strong>Wildcard Issue:</strong> ${item.result.issuewild || "N/A"
                            }</p>`;
                    } else if (Array.isArray(item.result)) {
                        contentDiv.innerHTML += `<p><strong>SSL Labs Results:</strong></p>`;
                        item.result.forEach((resultItem, index) => {
                            contentDiv.innerHTML += `<p>Result ${index + 1}: ${JSON.stringify(
                                resultItem
                            )}</p>`;
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
            tlsSecurityConfigElement.innerHTML =
                "<p>No TLS security configuration data available.</p>";
        }
    }
    load_tls_security();

    async function load_tls_cipher() {
        const response = await fetch("/fetch_tls_cipher", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify({ url_or_ip: urlOrIp }),
        });

        const data = await response.json();
        accumulatedData.push(data.tls_cipher);
        console.log("30: ", data);

        const tlsCipherSuitesElement = document.getElementById("tls-cipher");

        // Clear previous content
        tlsCipherSuitesElement.innerHTML = "";

        // Access the body from tls_cipher
        const cipherSuitesBody = data.tls_cipher?.body?.cipher_suites;

        if (
            cipherSuitesBody &&
            Array.isArray(cipherSuitesBody) &&
            cipherSuitesBody.length > 0
        ) {
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
                    contentDiv.innerHTML += `<p><strong>Curves:</strong> ${item.curves ? item.curves.join(", ") : "N/A"
                        }</p>`;
                    contentDiv.innerHTML += `<p><strong>OCSP Stapling:</strong> ${item.ocsp_stapling ? "Yes" : "No"
                        }</p>`;
                    contentDiv.innerHTML += `<p><strong>PFS:</strong> ${item.pfs || "N/A"
                        }</p>`;
                    contentDiv.innerHTML += `<p><strong>Protocols:</strong> ${item.protocols ? item.protocols.join(", ") : "N/A"
                        }</p>`;
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
            tlsCipherSuitesElement.innerHTML =
                "<p>No TLS cipher suite data available.</p>";
        }
    }
    load_tls_cipher();

    async function load_score_metrics() {
        const response = await fetch("/fetch_score_metrics", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify({ url_or_ip: urlOrIp }), // Assuming urlOrIp is defined in your code
        });

        // Log the response status and the raw JSON data
        const data = await response.json();
        console.log("Raw data: ", data); // Log the entire response for inspection

        accumulatedData.push(data.metrics_data); // Storing the fetched metrics in accumulatedData
        console.log("Score Metrics: ", data);

        const scoreElement = document.getElementById("score_metrics");
        scoreElement.innerHTML = "";

        // Check for score and explanations
        if (data.score !== undefined) { // Check if score is present
            scoreElement.innerHTML = `<p><strong>Score:</strong> ${data.score}</p><p><strong>Verdict:</string> ${data.verdict}</p><p><strong>Explanations:</strong></p><ul>${data.explanations.map(item => `<li><strong>${item.explanation}</strong><br><em>Risk:</em> ${item.risk}<br><em>Suggestion:</em> ${item.suggestion}</li><br>`).join('')}</ul>`;
        } else {
            scoreElement.innerHTML = "<p>No score data available</p>";
        }
    }
    load_score_metrics();
});

function downloadResults() {
    const jsonBlob = new Blob([JSON.stringify(accumulatedData, null, 2)], {
        type: "application/json",
    });
    const link = document.createElement("a");
    link.href = URL.createObjectURL(jsonBlob);
    link.download = "results.json"; // The filename for the download
    link.click(); // Trigger the download
}
