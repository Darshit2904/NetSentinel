# server.py
import socket
import requests

def get_server_location(url_or_ip):
    try:
        # Convert URL to IP address
        if url_or_ip.startswith("https://"):
            url_or_ip = url_or_ip[8:]  # Remove protocol
        elif url_or_ip.startswith("http://"):
            url_or_ip = url_or_ip[7:]  # Remove protocol

        # Remove trailing slash
        if url_or_ip.endswith("/"):
            url_or_ip = url_or_ip[:-1]

        # Get IP address
        ip_address = socket.gethostbyname(url_or_ip)

        # Fetch server location information from ip-api.com
        response = requests.get(f'http://ip-api.com/json/{ip_address}')
        data = response.json()
        # print(data)

        if data['status'] == 'fail':
            return {'error': data['message']}

        return data
    except socket.gaierror:
        return {'error': 'Invalid URL or IP address provided.'}
    except Exception as e:
        return {'error': str(e)}


# if __name__ == "__main__":
#     # Example usage
#     website_url = "https://www.google.co.uk/"
#     result = get_server_location(website_url)
#     print(result)