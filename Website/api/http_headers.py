import requests

def fetch_http_headers(url):
    try:
        response = requests.get(url)
        response.raise_for_status() 
        return dict(response.headers)
    except requests.RequestException as e:
        return {'error': str(e)}

# print(fetch_http_headers('https://www.google.com'))