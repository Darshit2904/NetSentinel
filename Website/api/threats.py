import os
import requests
import base64
import xml.etree.ElementTree as ET
from urllib.parse import urlparse
from dotenv import load_dotenv


load_dotenv()

def get_urlhaus_result(url):
    try:
        domain = urlparse(url).hostname
        response = requests.post(
            'https://urlhaus-api.abuse.ch/v1/host/',
            headers={'Content-Type': 'application/x-www-form-urlencoded'},
            data=f'host={domain}'
        )
        return response.json()
    except Exception as e:
        return {'error': f'Request to URLhaus failed: {str(e)}'}

def get_phishtank_result(url):
    try:
        encoded_url = base64.b64encode(url.encode()).decode('utf-8')
        endpoint = f'https://checkurl.phishtank.com/checkurl/?url={encoded_url}'
        headers = {'User-Agent': 'phishtank/web-check'}
        response = requests.post(endpoint, headers=headers, timeout=5)
        if response.status_code == 200:
            root = ET.fromstring(response.content)
            results = root.find('results')
            if results is not None:
                return {child.tag: child.find('in_database').text for child in results}
            else:
                return {'error': 'PhishTank response is not in expected format'}
        else:
            return {'error': f'Request to PhishTank failed with status code {response.status_code}'}
    except Exception as e:
        return {'error': f'Request to PhishTank failed: {str(e)}'}

def handle_threat_checks(url):
    try:
        urlhaus = get_urlhaus_result(url)
        phishtank = get_phishtank_result(url)
        
        return {
            'urlhaus': urlhaus,
            'phishtank': phishtank,
        }
    except Exception as e:
        return {'error': f'Error during threat checks: {str(e)}'}
    
# print(handle_threat_checks('https://www.google.com'))
