import requests, json
from urllib.parse import urlparse

MOZILLA_TLS_OBSERVATORY_API = 'https://tls-observatory.services.mozilla.com/api/v1'

def get_tls_security_config(url_or_ip):
    try:
        # Parse the domain from the provided URL or IP
        domain = urlparse(url_or_ip).hostname
        if not domain:
            return {'error': 'Invalid URL provided'}
        
        # Initiate the scan for the domain
        scan_response = requests.post(f'{MOZILLA_TLS_OBSERVATORY_API}/scan?target={domain}')
        scan_response.raise_for_status()
        scan_data = scan_response.json()
        scan_id = scan_data.get('scan_id')

        if not isinstance(scan_id, int):
            return {'error': 'Failed to get scan_id from TLS Observatory'}

        # Retrieve the results of the scan
        result_response = requests.get(f'{MOZILLA_TLS_OBSERVATORY_API}/results?id={scan_id}')
        result_response.raise_for_status()
        result_data = result_response.json()

        # Extract the security configuration data
        security_config = result_data.get('analysis', 'No data available')
        
        return {
            'status_code': 200,
            'body': security_config
        }
    except requests.RequestException as e:
        return {'status_code': 500, 'body': {'error': str(e)}}

# Example usage
if __name__ == "__main__":
    url_or_ip = "https://www.cricbuzz.com"
    security_config = get_tls_security_config(url_or_ip)
    # print(security_config)
    print(json.dumps(security_config, indent=4))