import asyncio
from api.who import fetch_whois_data
from api.dns_records import fetch_dns_data, get_dns_records
from api.archives import fetch_wayback_data
from api.carbon import fetch_carbon_footprint
from api.blocklist import check_domain_against_blocklists
from api.status import check_status
from api.traceroute import run_traceroute
from api.threats import handle_threat_checks
from api.port import ports_handler
from api.sitemap import handle_sitemap_check
from api.Firewall import detect_waf
from api.metadata import fetch_metadata
from api.http_headers import fetch_http_headers
from api.hsts import check_hsts
from api.security_headers import check_security_headers
from api.domain_rank import check_domain_rank
from api.link import analyze_links
from api.mail_server import analyze_mail_servers
from api.ssl_certificate import fetch_ssl_certificate
from api.tranco import fetch_tranco_rank 
from api.dnssec_records import fetch_dnssec_records
from api.redirects import handle_redirects
from api.security_txt import handler as fetch_security_txt_data
from api.robots import handler as fetch_robots_txt_data
from api.screenshot import capture_screenshot
from api.server import get_server_location 
from api.tls_handshake_simulation import get_tls_handshake_details
from api.tls_security_issues import get_tls_security_config
from api.tls_cipher_suites import get_tls_cipher_suites
from scoremetrics import check_websites

class DAO:
    @staticmethod
    def get_whois_data(url_or_ip):
        try:
            return fetch_whois_data(url_or_ip)
        except Exception as e:
            return {'error': str(e)}

    @staticmethod
    def get_dns_data(url_or_ip):
        try:
            return fetch_dns_data(url_or_ip)
        except Exception as e:
            return {'error': str(e)}

    @staticmethod
    def get_dns_records(url_or_ip):
        try:
            return get_dns_records(url_or_ip)
        except Exception as e:
            return {'error': str(e)}

    @staticmethod
    def get_wayback_data(url_or_ip):
        try:
            return fetch_wayback_data(url_or_ip)
        except Exception as e:
            return {'error': str(e)}

    @staticmethod
    def get_carbon_footprint(url_or_ip):
        try:
            return fetch_carbon_footprint(url_or_ip)
        except Exception as e:
            return {'error': str(e)}

    @staticmethod
    def get_status(url_or_ip):
        try:
            return check_status(url_or_ip)
        except Exception as e:
            return {'error': str(e)}

    @staticmethod
    def get_traceroute(url_or_ip):
        try:
            return run_traceroute(url_or_ip)
        except Exception as e:
            return {'error': str(e)}

    @staticmethod
    def get_blocklist_results(url_or_ip):
        try:
            return check_domain_against_blocklists(url_or_ip)
        except Exception as e:
            return {'error': str(e)}


    @staticmethod
    def get_threats_data(url_or_ip):
        try:
            return handle_threat_checks(url_or_ip)
        except Exception as e:
            return {'error': str(e)}

 
    @staticmethod
    def get_port_check_data(url_or_ip):
        try:
            return asyncio.run(ports_handler(url_or_ip))
        except Exception as e:
            return {'error': str(e)}


    @staticmethod
    def get_sitemap_data(url_or_ip):
        sitemap_handler = handle_sitemap_check()
        return sitemap_handler.get_sitemap(url_or_ip)


    @staticmethod
    def get_waf_data(url_or_ip):
        try:
            return detect_waf(url_or_ip)
        except Exception as e:
            return {'error': str(e)}

    @staticmethod
    def get_metadata(url_or_ip):
        try:
            return fetch_metadata(url_or_ip)
        except Exception as e:
            return {'error': str(e)}

    @staticmethod
    def get_http_headers(url_or_ip):
        try:
            return fetch_http_headers(url_or_ip)
        except Exception as e:
            return {'error': str(e)}

    @staticmethod
    def get_hsts_data(url_or_ip):
        try:
            return check_hsts(url_or_ip)
        except Exception as e:
            return {'error': str(e)}

    @staticmethod
    def get_security_headers(url_or_ip):
        try:
            return check_security_headers(url_or_ip)
        except Exception as e:
            return {'error': str(e)}

    @staticmethod
    def get_domain_rank(url_or_ip):
        try:
            return check_domain_rank(url_or_ip)
        except Exception as e:
            return {'error': str(e)}

    @staticmethod
    def get_link_analysis(url_or_ip):
        try:
            return analyze_links(url_or_ip)
        except Exception as e:
            return {'error': str(e)}

    @staticmethod
    def get_mail_server_analysis(url_or_ip):
        try:
            return analyze_mail_servers(url_or_ip)
        except Exception as e:
            return {'error': str(e)}

    @staticmethod
    def get_ssl_certificate(url_or_ip):
        try:
            return fetch_ssl_certificate(url_or_ip)
        except Exception as e:
            return {'error': str(e)}

    @staticmethod
    def get_tranco_rank(Domain):
        try:
            return fetch_tranco_rank(Domain)
        except Exception as e:
            return {'error': str(e)}
    
    @staticmethod
    def get_dnssec_data(domain):
      try:
          return fetch_dnssec_records(domain)
      except Exception as e:
            return {'error': str(e)}
      
    @staticmethod
    def get_redirects(url_or_ip):
        try:
            return handle_redirects(url_or_ip)
        except Exception as e:
            return {'error': str(e)}
    
    @staticmethod
    def get_security_txt_data(url_or_ip):
        try:
            return fetch_security_txt_data(url_or_ip)
        except Exception as e:
            return {'error': str(e)}
    
    @staticmethod
    def get_robots_txt_data(url_or_ip):
        try:
            return fetch_robots_txt_data(url_or_ip)
        except Exception as e:
            return {'error': str(e)}
        

    @staticmethod
    async def capture_screenshot(url):  
        try:
            screenshot_bytes = await capture_screenshot(url)
            screenshot_path = 'static/screenshots/screenshot.png'  

            with open(screenshot_path, 'wb') as f:
                f.write(screenshot_bytes)

            return screenshot_path  
        except Exception as e:
            return {'error': str(e)}
        
    @staticmethod
    def get_server_location(url_or_ip):
        try:
            return get_server_location(url_or_ip) 
        except Exception as e:
            return {'error': str(e)}
    
    @staticmethod
    def get_tls_handshake_simulation(url_or_ip):
        try:
            return get_tls_handshake_details(url_or_ip)
        except Exception as e:
            return {'error': str(e)}
        
    @staticmethod
    def get_tls_security_config(url_or_ip):
        try:
            return get_tls_security_config(url_or_ip)
        except Exception as e:
            return {'error': str(e)}
        
    @staticmethod
    def get_tls_cipher_suites(url_or_ip):
        try:
            return get_tls_cipher_suites(url_or_ip)
        except Exception as e:
            return {'error': str(e)}
        
    @staticmethod
    async def get_score_metrics(url_or_ip):
        try:
            return await check_websites(url_or_ip)
        except Exception as e:
            return {'error': str(e)}