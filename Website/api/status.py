import requests
import time

def check_status(url):
    if not url:
        raise ValueError('You must provide a URL!')

    start_time = time.time()

    try:
        response = requests.get(url)
        response.raise_for_status()  
        status_code = response.status_code
        response_time = (time.time() - start_time) * 1000  
        return {'isUp': True, 'responseCode': status_code, 'responseTime': response_time}

    except requests.exceptions.RequestException as e:
        raise ValueError(f'Error fetching URL: {str(e)}')
