import requests

def has_waf(waf):
    return {
        'hasWaf': True,
        'waf': waf,
    }

def detect_waf(url):
    full_url = url if url.startswith('http') else f'http://{url}'

    try:
        response = requests.get(full_url)
        headers = response.headers

        if 'server' in headers and 'cloudflare' in headers['server']:
            return has_waf('Cloudflare')
        if 'x-powered-by' in headers and 'AWS Lambda' in headers['x-powered-by']:
            return has_waf('AWS WAF')
        if 'server' in headers and 'AkamaiGHost' in headers['server']:
            return has_waf('Akamai')
        if 'server' in headers and 'Sucuri' in headers['server']:
            return has_waf('Sucuri')
        if 'server' in headers and 'BarracudaWAF' in headers['server']:
            return has_waf('Barracuda WAF')
        if 'server' in headers and ('F5 BIG-IP' in headers['server'] or 'BIG-IP' in headers['server']):
            return has_waf('F5 BIG-IP')
        if 'x-sucuri-id' in headers or 'x-sucuri-cache' in headers:
            return has_waf('Sucuri CloudProxy WAF')
        if 'server' in headers and 'FortiWeb' in headers['server']:
            return has_waf('Fortinet FortiWeb WAF')
        if 'server' in headers and 'Imperva' in headers['server']:
            return has_waf('Imperva SecureSphere WAF')
        if 'x-protected-by' in headers and 'Sqreen' in headers['x-protected-by']:
            return has_waf('Sqreen')
        if 'x-waf-event-info' in headers:
            return has_waf('Reblaze WAF')
        if 'set-cookie' in headers and '_citrix_ns_id' in headers['set-cookie']:
            return has_waf('Citrix NetScaler')
        if 'x-denied-reason' in headers or 'x-wzws-requested-method' in headers:
            return has_waf('WangZhanBao WAF')
        if 'x-webcoment' in headers:
            return has_waf('Webcoment Firewall')
        if 'server' in headers and 'Yundun' in headers['server']:
            return has_waf('Yundun WAF')
        if 'x-yd-waf-info' in headers or 'x-yd-info' in headers:
            return has_waf('Yundun WAF')
        if 'server' in headers and 'Safe3WAF' in headers['server']:
            return has_waf('Safe3 Web Application Firewall')
        if 'server' in headers and 'NAXSI' in headers['server']:
            return has_waf('NAXSI WAF')
        if 'x-datapower-transactionid' in headers:
            return has_waf('IBM WebSphere DataPower')

        return {'hasWaf': False}
    except requests.RequestException as e:
        return {
            'error': str(e)
        }

# print(detect_waf('https://www.google.com'))