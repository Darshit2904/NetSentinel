import requests, json
from urllib.parse import urlparse

MOZILLA_TLS_OBSERVATORY_API = 'https://tls-observatory.services.mozilla.com/api/v1'

def get_tls_cipher_suites(url_or_ip):
    try:
      
        domain = urlparse(url_or_ip).hostname
        if not domain:
            return {'error': 'Invalid URL provided'}
        
      
        scan_response = requests.post(f'{MOZILLA_TLS_OBSERVATORY_API}/scan?target={domain}')
        scan_response.raise_for_status() 
        scan_data = scan_response.json()
        scan_id = scan_data.get('scan_id')

        if not isinstance(scan_id, int):
            return {'error': 'Failed to get scan_id from TLS Observatory'}

     
        result_response = requests.get(f'{MOZILLA_TLS_OBSERVATORY_API}/results?id={scan_id}')
        result_response.raise_for_status()  
        result_data = result_response.json()

    
        connection_info = result_data.get('connection_info', {})
        cipher_suites = connection_info.get('ciphersuite', [])

      
        formatted_cipher_suites = [
            {
                'cipher': cs.get('cipher'),
                'protocols': cs.get('protocols'),
                'pubkey': cs.get('pubkey'),
                'sigalg': cs.get('sigalg'),
                'ticket_hint': cs.get('ticket_hint'),
                'ocsp_stapling': cs.get('ocsp_stapling'),
                'pfs': cs.get('pfs'),
                'curves': cs.get('curves')
            }
            for cs in cipher_suites
        ]

        tls_data = {
            'cipher_suites': formatted_cipher_suites if formatted_cipher_suites else 'No data available'
        }

        return {
            'status_code': 200,
            'body': tls_data
        }
    except requests.RequestException as e:
        return {'status_code': 500, 'body': {'error': str(e)}}


# # Example usage
# if __name__ == "__main__":
#     url_or_ip = "https://www.cricbuzz.com"
#     security_config = get_tls_cipher_suites(url_or_ip)
#     print(json.dumps(security_config, indent=4))
