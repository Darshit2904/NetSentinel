import requests

def check_security_headers(url):
    try:
       
        if not url.startswith(('http://', 'https://')):
            url = f'http://{url}'

        response = requests.get(url)
        headers = response.headers

        return {
            'strictTransportPolicy': 'strict-transport-security' in headers,
            'xFrameOptions': 'x-frame-options' in headers,
            'xContentTypeOptions': 'x-content-type-options' in headers,
            'xXSSProtection': 'x-xss-protection' in headers,
            'contentSecurityPolicy': 'content-security-policy' in headers
        }

    except requests.RequestException as e:
        return {
            'statusCode': 500,
            'error': str(e)
        }

# print(check_security_headers('https://www.google.com'))