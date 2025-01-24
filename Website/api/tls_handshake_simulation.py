import ssl
import socket

# Full mapping for Protocol Codes
protocol_code_map = {
    "SSLv3": 0x0300,
    "TLSv1": 0x0301,
    "TLSv1.1": 0x0302,
    "TLSv1.2": 0x0303,
    "TLSv1.3": 0x0304,
}

# Comprehensive mapping for Cipher Suite Codes
cipher_suite_code_map = {
    # TLS 1.2
    "TLS_RSA_WITH_NULL_MD5": 0x0001,
    "TLS_RSA_WITH_NULL_SHA": 0x0002,
    "TLS_RSA_WITH_RC4_128_MD5": 0x0004,
    "TLS_RSA_WITH_RC4_128_SHA": 0x0005,
    "TLS_RSA_WITH_3DES_EDE_CBC_SHA": 0x000A,
    "TLS_RSA_WITH_AES_128_CBC_SHA": 0x002F,
    "TLS_RSA_WITH_AES_256_CBC_SHA": 0x0035,
    "TLS_RSA_WITH_AES_128_GCM_SHA256": 0x009C,
    "TLS_RSA_WITH_AES_256_GCM_SHA384": 0x009D,
    "TLS_RSA_WITH_AES_128_CCM": 0xC0AC,
    "TLS_RSA_WITH_AES_256_CCM": 0xC0AD,
    
    # ECDHE Suites
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA": 0xC013,
    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA": 0xC014,
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256": 0xC02F,
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384": 0xC030,
    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA": 0xC009,
    "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA": 0xC00A,
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256": 0xC02B,
    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384": 0xC02C,

    # DHE Suites
    "TLS_DHE_RSA_WITH_AES_128_CBC_SHA": 0x0033,
    "TLS_DHE_RSA_WITH_AES_256_CBC_SHA": 0x0039,
    "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256": 0x00D0,
    "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384": 0x00D1,
    
    # CHACHA20
    "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305": 0xCC14,
    "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305": 0xCC13,
    
    # Legacy Cipher Suites
    "TLS_RSA_WITH_DES_CBC_SHA": 0x0009,
    "TLS_RSA_WITH_3DES_EDE_CBC_SHA": 0x000A,
    "TLS_RSA_WITH_AES_128_CBC_SHA256": 0x003C,
    "TLS_RSA_WITH_AES_256_CBC_SHA256": 0x003D,
    "TLS_RSA_WITH_RC4_128_SHA": 0x0005,
    
    # Additional Ciphers for TLS 1.3
    "TLS_AES_128_GCM_SHA256": 0x1301,
    "TLS_AES_256_GCM_SHA384": 0x1302,
    "TLS_CHACHA20_POLY1305": 0x1303,
    
    # Add more cipher suites as needed
}

# Comprehensive mapping for Curve Codes
curve_code_map = {
    "secp256r1": 0x0017,  # Also known as prime256v1
    "secp384r1": 0x0018,
    "secp521r1": 0x0019,
    "X25519": 0x001D,
    "brainpoolP256r1": 0x001A,
    "brainpoolP384r1": 0x001B,
    "brainpoolP512r1": 0x001C,
    "secp224r1": 0x0016,
    "secp192r1": 0x0015,
    "secp256k1": 0x0014,  # Common in Bitcoin
    "ed25519": 0x001E,    # Common in some modern applications
    # Add more curves as needed
}

# List of user agents you provided


# Function to get TLS handshake details
def get_tls_handshake_details(url):
    results = []
    user_agents = [
    "Android 2.3.7", "Android 4.0.4", "Android 4.1.1", "Android 4.2.2", "Android 4.3", "Android 4.4.2", "Android 5.0.0", "Android 6.0", "Android 7.0", "Android 7.0", "Android 8.0", "Android 8.1", "Android 9.0", "Baidu Jan 2015", "BingBot Dec 2013", "BingPreview Dec 2013", "BingPreview Jun 2014", "BingPreview Jan 2015", "Chrome (on Win 7)", "Chrome (on Win 7)", "Chrome (on Win 7)", "Chrome (on Win 7)","Chrome (on Win 7)", "Chrome (on Win 7)", "Chrome (on OS X)", "Chrome (on Win 7)", "Chrome (on Win 7)", "Chrome (on OS X)", "Chrome (on OS X)", "Chrome (on OS X)", "Chrome (on OS X)", "Chrome (on OS X)", "Chrome (on OS X)", "Chrome (on OS X)", "Chrome (on OS X)", "Chrome (on Win 7)", "Chrome (on XP SP3)", "Chrome (on Win 7)", "Chrome (on Win 7)", "Chrome (on Win 7)", "Chrome (on Win 7)", "Chrome (on Win 7)", "Chrome (on Win 10)", "Chrome (on Win 10)", "Chrome (on Win 10)", "Firefox (on Win 7)", "Firefox (on Win 7)", "Firefox (on Win 7)", "Firefox (on Win 7)", "Firefox (on Win 7)", "Firefox (on Fedora 19)", "Firefox (on Win 7)", "Firefox (on Win 7)", "Firefox (on Win 8)", "Firefox (on Win 8)", "Firefox (on OS X)", "Firefox (on OS X)", "Firefox (on OS X)", "Firefox (on OS X)", "Firefox (on OS X)", "Firefox (on OS X)", "Firefox (on OS X)", "Firefox (on OS X)", "Firefox (on OS X)", "Firefox (on OS X)", "Firefox (on OS X)", "Firefox (on Win 7)", "Firefox (on Win 7)", "Firefox (on Win 7)", "Firefox (on XP SP3)", "Firefox (on Win 7)", "Firefox (on Win 7)", "Firefox (on Win 7)", "Firefox (on Win 7)", "Firefox (on Win 10)", "Firefox (on Win 10)", "Googlebot Oct 2013", "Googlebot Jun 2014", "Googlebot Feb 2015", "Googlebot Feb 2018", "IE 6", "IE 6", "IE (on Vista)", "IE (on XP)", "IE (on XP)", "IE (on Win 7)", "IE (on Win 7)", "IE (on Win 7)", "IE (on Win 7)", "IE (on Win 7)", "IE (on Win 7)", "IE (on Win 7)", "IE (on Win 7)", "IE (on Win 7)", "IE (on Win 10 Preview)", "IE (on Win 8.1)", "IE (on Win 8.1)", "IE (on Win 8.1)", "IE (on Win 8.1)", "IE (on Win 8.1)", "IE (on Win Phone 8.0)", "IE (on Win Phone 8.1)", "IE (on Win Phone 8.1 Update)", "IE (on Win 10)", "IE (on Win 10)", "Edge (on Win 10)", "Edge (on Win 10)", "Edge (on Win 10)", "Edge (on Win 10)", "Edge (on Win 10)", "Edge (on Win 10)", "Edge (on Win Phone 10)", "Java 6u45", "Java 7u25", "Java 8b132", "Java 8u31", "Java 8u111", "Java 8u161", "Java 9.0.4", "Java 11.0.3", "Java 12.0.1", "OpenSSL 0.9.8y", "OpenSSL 1.0.1h", "OpenSSL 1.0.1l", "OpenSSL 1.0.2e", "OpenSSL 1.0.2s", "OpenSSL 1.1.0k", "OpenSSL 1.1.1c", "Opera (on Win 7)", "Opera (on Win 7)", "Opera (on Win 7)", "Opera (on Win 7)", "Opera (on Win 10)", "Opera (on Win 10)", "Safari (on iOS 5.1.1)", "Safari (on OS X 10.6.8)", "Safari (on iOS 6.0.1)", "Safari (on OS X 10.8.4)", "Safari (on iOS 7.1)", "Safari (on iOS 8.0 Beta)", "Safari (on OS X 10.9)", "Safari (on iOS 8.4)", "Safari (on OS X 10.10)", "Safari (on iOS 9)", "Safari (on OS X 10.11)", "Safari (on iOS 10)", "Safari (on OS X 10.12)", "Safari (on MacOS 10.14.6 Beta)", "Safari (on iOS 12.3.1)", "Apple ATS (on iOS 9)", "Tor (on Win 7)", "Yahoo Slurp Oct 2013", "Yahoo Slurp Jun 2014", "Yahoo Slurp Jan 2015", "YandexBot 3.0", "YandexBot May 2014", "YandexBot Sep 2014", "YandexBot Jan 2015"
]
    host = url.split("://")[-1]
    print(host)
    if '/' in host:
            host = host.split('/')[0]
    port = 443

    # Create an SSL context with desired settings
    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_2  # Set minimum version to TLS 1.2
    context.maximum_version = ssl.TLSVersion.TLSv1_3  # Set maximum version to TLS 1.3

    for user_agent in user_agents:
        try:
            # Create a socket and wrap it with SSL
            with socket.create_connection((host, port)) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    # Send a request with a specific User-Agent
                    request = f"GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {user_agent}\r\nConnection: close\r\n\r\n"
                    ssock.send(request.encode())

                    # Output details about the handshake
                    protocol = ssock.version()
                    cipher = ssock.cipher()
                    cipher_name = cipher[0]
                    curve = "N/A"

                    # Attempt to extract the curve name based on cipher suite
                    if "ECDHE" in cipher_name:
                        # Map ECDHE cipher suites to their corresponding curves
                        ecdhe_curve_map = {
                            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256": "secp256r1",
                            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384": "secp384r1",
                            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256": "secp256r1",
                            "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384": "secp384r1",
                            "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305": "X25519",
                            "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305": "X25519",
                            # Add additional mappings for other ECDHE ciphers as needed
                        }
                        curve = ecdhe_curve_map.get(cipher_name, "N/A")

                    # Manual mappings
                    protocol_code = protocol_code_map.get(protocol, "Unknown Protocol Code")
                    cipher_suite_code = cipher_suite_code_map.get(cipher_name, "Unknown Cipher Suite Code")
                    curve_code = curve_code_map.get(curve, "Unknown Curve Code")

                    result = {
                        'user_agent': user_agent,
                        'curve': curve,
                        'protocol': protocol,
                        'cipher_suite': cipher_name,
                        'protocol_code': protocol_code,
                        'cipher_suite_code': cipher_suite_code,
                        'curve_code': curve_code
                    }

        except Exception as e:
            result = {
                'user_agent': user_agent,
                'handshake_status': 'Failed',
                'error': str(e)
            }
        results.append(result)
    return results

# url = "https://www.google.com"
# tls_details = get_tls_handshake_details(url)
# for detail in tls_details:
#     print(detail)
