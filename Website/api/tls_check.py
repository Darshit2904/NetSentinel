import requests

def check_tls(url):
    try:
        response = requests.get(url, timeout=5)
        return response.url.startswith('https://')
    except requests.RequestException:
        return False
    
# print(check_tls('https://www.google.com'))