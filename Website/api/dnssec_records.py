import requests
from urllib.parse import urlparse

def fetch_dnssec_records(domain_url):
    domain = urlparse(domain_url).hostname or domain_url
    dns_types = ['DNSKEY', 'DS', 'RRSIG']
    records = {}

    for dns_type in dns_types:
        url = f"https://dns.google/resolve?name={domain}&type={dns_type}"

        try:
            response = requests.get(url, headers={'Accept': 'application/dns-json'}, timeout=5)
            response.raise_for_status()
            dns_response = response.json()

            if 'Answer' in dns_response:
                records[dns_type] = {'isFound': True, 'answer': dns_response['Answer']}
            else:
                records[dns_type] = {'isFound': False, 'answer': None}
        except requests.exceptions.RequestException as e:
            records[dns_type] = {'error': f'Error fetching {dns_type} record: {str(e)}'}

    return records

# print(fetch_dnssec_records("https://www.google.com"))
