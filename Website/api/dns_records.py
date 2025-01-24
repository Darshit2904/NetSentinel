import socket
import dns.resolver
from urllib.parse import urlparse

def fetch_dns_data(domain):
    try:
        ip = socket.gethostbyname(domain)
        return {'ip': ip}
    except Exception as e:
        return {'error': str(e)}

def get_dns_records(url):
    try:
        # Check if the URL starts with 'http://' or 'https://'
        if not (url.startswith('http://') or url.startswith('https://')):
            url = 'http://' + url  # Add a scheme if it's missing

        # Parse the hostname from the URL
        parsed_url = urlparse(url)
        domain = parsed_url.hostname

        if not domain:
            return {'error': 'Invalid URL or domain name'}

        # Remove all occurrences of 'www.' from the domain
        domain = domain.replace('www.', '')

        resolver = dns.resolver.Resolver()
        resolver.timeout = 10  
        resolver.lifetime = 30 

        records = {}
        record_types = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME', 'SOA', 'SRV', 'PTR']

        for rtype in record_types:
            try:
                response = resolver.resolve(domain, rtype)
                if rtype == 'TXT':
                    records[rtype] = [{'name': domain, 'type': rtype, 'text': [record.decode('utf-8') for record in record.strings]} for record in response]
                else:
                    records[rtype] = [{'name': str(record), 'type': rtype, 'address': record.to_text()} for record in response]
            except dns.resolver.NoAnswer:
                records[rtype] = []
            except dns.resolver.NXDOMAIN:
                records[rtype] = {'error': 'Domain does not exist'}
            except dns.resolver.Timeout:
                records[rtype] = {'error': f'Timeout while fetching {rtype} records'}
            except Exception as e:
                records[rtype] = {'error': f'Error fetching {rtype} records: {str(e)}'}

        return records

    except Exception as e:
        return {'error': f'Error resolving DNS: {str(e)}'}

