import dns.resolver

def check_domain_against_blocklists(url_or_ip):
    known_block_ips = [
        '146.112.61.106', '185.228.168.10', '8.26.56.26', '9.9.9.9', '208.69.38.170',
        '208.69.39.170', '208.67.222.222', '208.67.222.123', '199.85.126.10', '199.85.126.20',
        '156.154.70.22', '77.88.8.7', '77.88.8.8', '::1', '2a02:6b8::feed:0ff', '2a02:6b8::feed:bad',
        '2a02:6b8::feed:a11', '2620:119:35::35', '2620:119:53::53', '2606:4700:4700::1111',
        '2606:4700:4700::1001', '2001:4860:4860::8888', '2a0d:2a00:1::', '2a0d:2a00:2::'
    ]
    dns_servers = [
        {'name': 'AdGuard', 'ip': '176.103.130.130'},
        {'name': 'AdGuard Family', 'ip': '176.103.130.132'},
        {'name': 'CleanBrowsing Adult', 'ip': '185.228.168.10'},
        {'name': 'CleanBrowsing Family', 'ip': '185.228.168.168'},
        {'name': 'CleanBrowsing Security', 'ip': '185.228.168.9'},
        {'name': 'CloudFlare', 'ip': '1.1.1.1'},
        {'name': 'CloudFlare Family', 'ip': '1.1.1.3'},
        {'name': 'Comodo Secure', 'ip': '8.26.56.26'},
        {'name': 'Google DNS', 'ip': '8.8.8.8'},
        {'name': 'Neustar', 'ip': '156.154.70.22'},
        {'name': 'OpenDNS Family', 'ip': '208.67.222.123'},
        {'name': 'OpenDNS Home', 'ip': '208.67.222.222'},
        {'name': 'OpenDNS VIP', 'ip': '208.67.222.220'},
        {'name': 'OpenDNS VIP Custom', 'ip': '208.67.222.222'}
    ]

    results = []
    for server in dns_servers:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [server['ip']]
        try:
            answer = resolver.resolve(url_or_ip, 'A')
            ip = answer[0].address
            results.append({
                'server': server['name'],
                'ip': ip,
                'is_blocked': ip in known_block_ips
            })
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            results.append({
                'server': server['name'],
                'ip': None,
                'is_blocked': False
            })
        except Exception as e:
            results.append({
                'server': server['name'],
                'error': str(e)
            })
    return results
