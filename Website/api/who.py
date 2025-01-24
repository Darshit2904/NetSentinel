import whois

def fetch_whois_data(url_or_ip):
    try:
        whois_data = whois.whois(url_or_ip)
        return whois_data
    except Exception as e:
        return {'error': f'Error fetching WHOIS data: {str(e)}'}

# print(fetch_whois_data('google.com'))
