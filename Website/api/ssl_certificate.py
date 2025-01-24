import ssl
import socket
from urllib.parse import urlparse

def fetch_ssl_certificate(url_string):
    try:
        parsed_url = urlparse(url_string)
        hostname = parsed_url.hostname
        port = parsed_url.port or 443

      
        context = ssl.create_default_context()

    
        with socket.create_connection((hostname, port)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                
                cert = ssock.getpeercert()
                if not cert:
                    raise ValueError(
                        "No certificate presented by the server.\n"
                        "The server is possibly not using SNI (Server Name Indication) "
                        "to identify itself, or it may be due to an invalid SSL certificate, "
                        "or an incomplete SSL handshake at the time the cert is being read."
                    )

                return cert
    except Exception as e:
        raise RuntimeError(f"Error fetching site certificate: {e}")


# print(fetch_ssl_certificate('https://www.google.com'))