import requests

def handle_redirects(url_or_ip):
    # Ensure the URL starts with 'http://' or 'https://'
    if not url_or_ip.startswith(('http://', 'https://')):
        url_or_ip = 'http://' + url_or_ip

    redirects = [url_or_ip]
    try:
        response = requests.get(url_or_ip, allow_redirects=False, timeout=10)
        
        while response.is_redirect and len(redirects) < 12:
            location = response.headers.get('Location')
            if location:
                # Ensure the redirected URL starts with 'http://' or 'https://'
                if not location.startswith(('http://', 'https://')):
                    location = 'http://' + location
                redirects.append(location)
                response = requests.get(location, allow_redirects=False, timeout=10)
            else:
                break
                
        return {'redirects': redirects}

    except requests.RequestException as e:
        raise Exception(f"Error: {str(e)}")

