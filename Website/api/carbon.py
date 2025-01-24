import requests

def get_html_size(url):
    try:
        response = requests.get(url)
        size_in_bytes = len(response.text.encode('utf-8'))
        return size_in_bytes
    except Exception as e:
        return {'error': f'Error fetching HTML size: {str(e)}'}

def fetch_carbon_footprint(url):
    try:
        html_size = get_html_size(url)
        if isinstance(html_size, dict) and 'error' in html_size:
            return html_size
        
        api_url = f'https://api.websitecarbon.com/data?bytes={html_size}&green=0'
        response = requests.get(api_url)
        carbon_data = response.json()

        if 'statistics' not in carbon_data or (carbon_data['statistics']['adjustedBytes'] == 0 and carbon_data['statistics']['energy'] == 0):
            return {'skipped': 'Not enough info to get carbon data'}
        
        carbon_data['scanUrl'] = url
        return carbon_data
    except Exception as e:
        return {'error': f'Error fetching carbon data: {str(e)}'}
