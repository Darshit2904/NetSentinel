from dao import DAO

class Service:
    @staticmethod
    def get_whois_data(url_or_ip):
        return DAO.get_whois_data(url_or_ip)

    @staticmethod
    def get_dns_data(domain):
        return DAO.get_dns_data(domain)

    @staticmethod
    def get_dns_records(domain):
        return DAO.get_dns_records(domain)

    @staticmethod
    def get_wayback_data(url_or_ip):
        return DAO.get_wayback_data(url_or_ip)

    @staticmethod
    def get_carbon_footprint(url_or_ip):
        return DAO.get_carbon_footprint(url_or_ip)

    @staticmethod
    def get_status(url_or_ip):
        return DAO.get_status(url_or_ip)

    @staticmethod
    def get_traceroute(url_or_ip):
        return DAO.get_traceroute(url_or_ip)

    @staticmethod
    def get_blocklist_results(url_or_ip):
        return DAO.get_blocklist_results(url_or_ip)

    @staticmethod
    def get_threats_data(url_or_ip):
        return DAO.get_threats_data(url_or_ip)

    @staticmethod
    def get_port_check_data(url_or_ip):
        return DAO.get_port_check_data(url_or_ip)

    
    @staticmethod
    def get_sitemap_data(url_or_ip):
        return DAO.get_sitemap_data(url_or_ip)

    @staticmethod
    def get_waf_data(url_or_ip):
        return DAO.get_waf_data(url_or_ip)

    @staticmethod
    def get_metadata(url_or_ip):
        return DAO.get_metadata(url_or_ip)

    @staticmethod
    def get_http_headers(url_or_ip):
        return DAO.get_http_headers(url_or_ip)

    @staticmethod
    def get_hsts_data(url_or_ip):
        return DAO.get_hsts_data(url_or_ip)

    @staticmethod
    def get_security_headers(url_or_ip):
        return DAO.get_security_headers(url_or_ip)

    @staticmethod
    def get_domain_rank(url_or_ip):
        return DAO.get_domain_rank(url_or_ip)

    @staticmethod
    def get_link_analysis(url_or_ip):
        return DAO.get_link_analysis(url_or_ip)

    @staticmethod
    def get_mail_server_analysis(url_or_ip):
        return DAO.get_mail_server_analysis(url_or_ip)

    @staticmethod
    def get_ssl_certificate(url_or_ip):
        return DAO.get_ssl_certificate(url_or_ip)

    @staticmethod
    def get_tranco_rank(Domain):
        return DAO.get_tranco_rank(Domain)
    
    @staticmethod
    def get_dnssec_data(domain):
        return DAO.get_dnssec_data(domain)
    
    @staticmethod
    def get_redirects(url_or_ip):
        return DAO.get_redirects(url_or_ip)
    
    @staticmethod
    def get_security_txt_data(url_or_ip):
        return DAO.get_security_txt_data(url_or_ip)
    
    @staticmethod
    def get_robots_txt_data(url_or_ip):
        return DAO.get_robots_txt_data(url_or_ip)
    
    @staticmethod
    async def get_screenshot_data(url):
        try:
            return await DAO.capture_screenshot(url)  
        except Exception as e:
            return {'error': str(e)}
        
    @staticmethod
    def get_server_location(url_or_ip):
        return DAO.get_server_location(url_or_ip)  
    
    @staticmethod
    def get_tls_handshake_simulation(url_or_ip):
        return DAO.get_tls_handshake_simulation(url_or_ip)
    
    @staticmethod
    def get_tls_security_config(url_or_ip):
        return DAO.get_tls_security_config(url_or_ip)
    
    @staticmethod
    def get_tls_cipher_suites(url_or_ip):
        return DAO.get_tls_cipher_suites(url_or_ip)
    
    @staticmethod
    async def get_score_metrics(url_or_ip):
        return await DAO.get_score_metrics(url_or_ip)