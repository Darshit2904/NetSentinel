import dns.resolver
from urllib.parse import urlparse


def analyze_mail_servers(url):
    try:
       
        parsed_url = urlparse(url)
        domain = parsed_url.hostname or parsed_url.path

        
        mx_records = dns.resolver.resolve(domain, 'MX')

      
        txt_records = dns.resolver.resolve(domain, 'TXT')

     
        email_txt_records = []
        for txt in txt_records:
            record_string = ''.join([str(entry, 'utf-8') for entry in txt.strings])
            if (
                record_string.startswith('v=spf1') or
                record_string.startswith('v=DKIM1') or
                record_string.startswith('v=DMARC1') or
                record_string.startswith('protonmail-verification=') or
                record_string.startswith('google-site-verification=') or  # Google Workspace
                record_string.startswith('MS=') or  # Microsoft 365
                record_string.startswith('zoho-verification=') or  # Zoho
                record_string.startswith('titan-verification=') or  # Titan
                'bluehost.com' in record_string  # BlueHost
            ):
                email_txt_records.append(record_string)

       
        mail_services = []
        for record in email_txt_records:
            if record.startswith('protonmail-verification='):
                mail_services.append({'provider': 'ProtonMail', 'value': record.split('=')[1]})
            elif record.startswith('google-site-verification='):
                mail_services.append({'provider': 'Google Workspace', 'value': record.split('=')[1]})
            elif record.startswith('MS='):
                mail_services.append({'provider': 'Microsoft 365', 'value': record.split('=')[1]})
            elif record.startswith('zoho-verification='):
                mail_services.append({'provider': 'Zoho', 'value': record.split('=')[1]})
            elif record.startswith('titan-verification='):
                mail_services.append({'provider': 'Titan', 'value': record.split('=')[1]})
            elif 'bluehost.com' in record:
                mail_services.append({'provider': 'BlueHost', 'value': record})

      
        yahoo_mx = [record.exchange.to_text() for record in mx_records if 'yahoodns.net' in record.exchange.to_text()]
        if yahoo_mx:
            mail_services.append({'provider': 'Yahoo', 'value': yahoo_mx[0]})

       
        mimecast_mx = [record.exchange.to_text() for record in mx_records if 'mimecast.com' in record.exchange.to_text()]
        if mimecast_mx:
            mail_services.append({'provider': 'Mimecast', 'value': mimecast_mx[0]})

        return {
            'mxRecords': [record.exchange.to_text() for record in mx_records],
            'txtRecords': email_txt_records,
            'mailServices': mail_services
        }
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
        return {'skipped': 'No mail server in use on this domain'}
    except Exception as e:
        return {'error': str(e)}
