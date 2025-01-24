import requests
import os

def fetch_tranco_rank(domain):
    if not domain:
        raise ValueError('Invalid URL')
    
    try:
        auth = None
        if os.getenv('TRANCO_API_KEY'):
            auth = (os.getenv('TRANCO_USERNAME'), os.getenv('TRANCO_API_KEY'))
        
        response = requests.get(
            f'https://tranco-list.eu/api/ranks/domain/{domain}',
            timeout=5,
            auth=auth
        )
        response.raise_for_status()
        
        data = response.json()
        if not data or 'ranks' not in data or not data['ranks']:
            return {'skipped': f'Skipping, as {domain} isn\'t ranked in the top 100 million sites yet.'}
        
        return data
    
    except requests.RequestException as e:
        return {'error': f'Unable to fetch rank, {str(e)}'}
