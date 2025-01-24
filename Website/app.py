import logging
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask import Flask, render_template, request, jsonify , Response
from mailer import create_mail, send_email
from service import Service

app = Flask(__name__)
logging.basicConfig(level=logging.DEBUG)
mail = create_mail(app)

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["10 per day"],  
    storage_uri="memory://",  
)

@app.errorhandler(429)
def ratelimit_error(e):
    return render_template('error.html', error_message="You have exceeded your request limit. Try again after 24 hours."), 429

@app.route('/send_mail', methods=['POST'])
def send_mail_route():
    try:
        
        name = request.form['name']
        email = request.form['email']
        message = request.form['message']

        
        send_email(mail, app, name, email, message)  

        
        return jsonify({"status": "success", "message": "Email sent successfully!"})

    except Exception as e:
       
        return jsonify({"status": "error", "message": str(e)})

@app.route('/robots.txt')
def robots_txt():
    return Response(render_template('robots.txt'), mimetype='text/plain')

@app.route('/security.txt')
def security_txt():
    return Response(render_template('security.txt'), mimetype='text/plain')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/links')
def footer():
    return render_template('links.html')

@app.route('/contact')
def contact():
    return render_template('contact.html')

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/check', methods=['POST'])
def check():
    url_or_ip = request.form['url_or_ip']
    domain = url_or_ip.replace('https://', '').replace('http://', '').split('/')[0]

    return render_template('result.html', url_or_ip=url_or_ip)

@app.route('/fetch_score_metrics', methods=['POST'])
async def fetch_score_metrics():
    url_or_ip = request.json.get('url_or_ip')  

    results = await Service.get_score_metrics(url_or_ip)
    
    return results


@app.route('/fetch_whois_data', methods=['POST'])
def fetch_whois():
    url_or_ip = request.json.get('url_or_ip') 

    results = {}

    results['whois_data'] = Service.get_whois_data(url_or_ip)
    return jsonify(results)


@app.route('/fetch_dns_data', methods=['POST'])
def fetch_dns():
    url_or_ip = request.json.get('url_or_ip') 
    domain = url_or_ip.replace('https://', '').replace('http://', '').split('/')[0]

    results = {}

    results['dns_data'] = Service.get_dns_data(domain)
    return jsonify(results)


@app.route('/fetch_dns_records', methods=['POST'])
def fetch_dns_record_data():
    url_or_ip = request.json.get('url_or_ip') 
    domain = url_or_ip.replace('https://', '').replace('http://', '').split('/')[0]

    results = {}

    results['dns_records_data'] = Service.get_dns_records(domain)
    return jsonify(results)


@app.route('/fetch_wayback', methods=['POST'])
def fetch_wayback_data():
    url_or_ip = request.json.get('url_or_ip') 

    results = {}

    results['wayback_data'] = Service.get_wayback_data(url_or_ip)
    return jsonify(results)


@app.route('/fetch_carbon_footprint', methods=['POST'])
def fetch_carbon_footprint_data():
    url_or_ip = request.json.get('url_or_ip') 

    results = {}

    results['carbon_footprint_data'] = Service.get_carbon_footprint(url_or_ip)
    return jsonify(results)


@app.route('/fetch_status', methods=['POST'])
def fetch_status_data():
    url_or_ip = request.json.get('url_or_ip') 

    results = {}

    results['status_data'] = Service.get_status(url_or_ip)
    return jsonify(results)


@app.route('/fetch_traceroute', methods=['POST'])
def fetch_traceroute_data():
    url_or_ip = request.json.get('url_or_ip') 

    results = {}

    results['traceroute_data'] = Service.get_traceroute(url_or_ip)
    return jsonify(results)


@app.route('/fetch_blocklist', methods=['POST'])
def fetch_blocklist_data():
    url_or_ip = request.json.get('url_or_ip') 

    results = {}

    results['blocklist_results'] = Service.get_blocklist_results(url_or_ip)
    return jsonify(results)


@app.route('/fetch_threats', methods=['POST'])
def fetch_threats_data():
    url_or_ip = request.json.get('url_or_ip') 

    results = {}

    results['threats_data'] = Service.get_threats_data(url_or_ip)
    return jsonify(results)


@app.route('/fetch_port_check', methods=['POST'])
def fetch_port_check_data():
    url_or_ip = request.json.get('url_or_ip')
    results = {}

    results['port_check_data'] = Service.get_port_check_data(url_or_ip)
    return jsonify(results)


@app.route('/fetch_sitemap', methods=['POST'])
def fetch_sitemap_data():
    url_or_ip = request.json.get('url_or_ip') 

    results = {}
    results['sitemap_data'] = Service.get_sitemap_data(url_or_ip)
    return jsonify(results)


@app.route('/fetch_waf', methods=['POST'])
def fetch_waf_data():
    url_or_ip = request.json.get('url_or_ip') 

    results = {}

    results['waf_data'] = Service.get_waf_data(url_or_ip)
    return jsonify(results)


@app.route('/fetch_metadata', methods=['POST'])
def fetch_metadata_data():
    url_or_ip = request.json.get('url_or_ip') 

    results = {}

    results['metadata'] = Service.get_metadata(url_or_ip)
    return jsonify(results)


@app.route('/fetch_http_headers', methods=['POST'])
def fetch_http_headers_data():
    url_or_ip = request.json.get('url_or_ip') 

    results = {}

    results['http_headers'] = Service.get_http_headers(url_or_ip)
    return jsonify(results)


@app.route('/fetch_hsts', methods=['POST'])
def fetch_hsts_data():
    url_or_ip = request.json.get('url_or_ip') 

    results = {}

    results['hsts_data'] = Service.get_hsts_data(url_or_ip)
    return jsonify(results)


@app.route('/fetch_security_headers', methods=['POST'])
def fetch_security_headers_data():
    url_or_ip = request.json.get('url_or_ip') 

    results = {}

    results['security_headers'] = Service.get_security_headers(url_or_ip)
    return jsonify(results)


@app.route('/fetch_domain_rank', methods=['POST'])
def fetch_domain_rank_data():
    url_or_ip = request.json.get('url_or_ip') 

    results = {}

    results['domain_rank'] = Service.get_domain_rank(url_or_ip)
    return jsonify(results)


@app.route('/fetch_link_analysis', methods=['POST'])
def fetch_link_analysis_data():
    url_or_ip = request.json.get('url_or_ip') 

    results = {}

    results['link_analysis'] = Service.get_link_analysis(url_or_ip)
    return jsonify(results)


@app.route('/fetch_mail_server_analysis', methods=['POST'])
def fetch_lmail_server_analysis_data():
    url_or_ip = request.json.get('url_or_ip') 

    results = {}

    results['mail_server_analysis'] = Service.get_mail_server_analysis(url_or_ip)
    return jsonify(results)


@app.route('/fetch_ssl_certificate', methods=['POST'])
def fetch_ssl_certificate_data():
    url_or_ip = request.json.get('url_or_ip') 

    results = {}

    results['ssl_certificate'] = Service.get_ssl_certificate(url_or_ip)
    return jsonify(results)


@app.route('/fetch_tranco_rank', methods=['POST'])
def fetch_tranco_rank_data():
    url_or_ip = request.json.get('url_or_ip') 
    domain = url_or_ip.replace('https://', '').replace('http://', '').split('/')[0]

    results = {}

    results['tranco_rank'] = Service.get_tranco_rank(domain)
    return jsonify(results)

@app.route('/fetch_dnssec', methods=['POST'])
def fetch_dnssec_data():
    url_or_ip = request.json.get('url_or_ip') 
    domain = url_or_ip.replace('https://', '').replace('http://', '').split('/')[0]

    results = {}

    results['dnssec_data'] = Service.get_dnssec_data(domain)
    return jsonify(results)


@app.route('/fetch_redirects', methods=['POST'])
def fetch_redirects_data():
    url_or_ip = request.json.get('url_or_ip') 

    results = {}

    results['redirects'] = Service.get_redirects(url_or_ip) 
    return jsonify(results)


@app.route('/fetch_security_txt', methods=['POST'])
def fetch_security_txt_data():
    url_or_ip = request.json.get('url_or_ip') 

    results = {}

    results['security_txt_data'] = Service.get_security_txt_data(url_or_ip) 
    return jsonify(results)


@app.route('/fetch_robots_txt', methods=['POST'])
def fetch_robots_txt_data():
    url_or_ip = request.json.get('url_or_ip') 

    results = {}

    results['robots_txt_data'] = Service.get_robots_txt_data(url_or_ip)
    return jsonify(results)


@app.route('/fetch_screenshot', methods=['POST'])
async def fetch_screenshot_data():
    url_or_ip = request.json.get('url_or_ip')  
    results = {}

    results['screenshot_data'] = await Service.get_screenshot_data(url_or_ip)

    return jsonify(results)


@app.route('/fetch_server_location', methods=['POST'])
def fetch_server_location():
    url_or_ip = request.json.get('url_or_ip')
    
    results = {}
    results['server_location'] = Service.get_server_location(url_or_ip)
    
    return jsonify(results)

@app.route('/fetch_tls_handshake', methods=['POST'])
def fetch_tls_handshake():
    url_or_ip = request.json.get('url_or_ip') 
    
    results = {}
    results['tls_handshake'] = Service.get_tls_handshake_simulation(url_or_ip)  
    
    return jsonify(results)

@app.route('/fetch_tls_security' ,methods=['post'] )
def fetch_tls_security():
    url_or_ip = request.json.get('url_or_ip')

    results = {}
    results['tls_security'] = Service.get_tls_security_config(url_or_ip)

    return jsonify(results)


@app.route('/fetch_tls_cipher', methods=['POST'])
def fetch_tls_cipher():
    url_or_ip = request.json.get('url_or_ip') 

    results = {}

    results['tls_cipher'] = Service.get_tls_cipher_suites(url_or_ip)
    return jsonify(results)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True )
    
