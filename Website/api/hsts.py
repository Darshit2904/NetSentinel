import re
import requests

def check_hsts(url):
    try:
        response = requests.get(url, headers={'User-Agent': 'Mozilla/5.0'})
        hsts_header = response.headers.get('Strict-Transport-Security')

        if not hsts_header:
            return {
                'message': 'Site does not serve any HSTS headers.',
                'compatible': False,
                'hstsHeader': None
            }

        max_age_match = re.search(r'max-age=(\d+)', hsts_header)
        includes_sub_domains = 'includeSubDomains' in hsts_header
        preload = 'preload' in hsts_header

        if not max_age_match or int(max_age_match.group(1)) < 10886400:
            return {
                'message': 'HSTS max-age is less than 10886400.',
                'compatible': False,
                'hstsHeader': hsts_header
            }
        elif not includes_sub_domains:
            return {
                'message': 'HSTS header does not include all subdomains.',
                'compatible': False,
                'hstsHeader': hsts_header
            }
        elif not preload:
            return {
                'message': 'HSTS header does not contain the preload directive.',
                'compatible': False,
                'hstsHeader': hsts_header
            }
        else:
            return {
                'message': 'Site is compatible with the HSTS preload list!',
                'compatible': True,
                'hstsHeader': hsts_header
            }

    except requests.RequestException as e:
        return {
            'message': f'Error making request: {str(e)}',
            'compatible': False,
            'hstsHeader': None
        }
