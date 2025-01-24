import subprocess
from urllib.parse import urlparse

def run_traceroute(url_string):
   
    url_object = urlparse(url_string)
    host = url_object.hostname

    if not host:
        raise ValueError('Invalid URL provided')

  
    try:
        result = subprocess.run(['tracert', host], capture_output=True, text=True, check=True)
     
        output = result.stdout
       
        lines = output.splitlines()
        hops = [line for line in lines if line.startswith(host) or line]
        return {
            'message': 'Traceroute completed!',
            'result': hops
        }
    except subprocess.CalledProcessError as e:
        return {'error': f'Traceroute failed: {str(e)}'}
    except Exception as e:
        return {'error': f'An unexpected error occurred: {str(e)}'}

def handler(url_string):
    try:
        return run_traceroute(url_string)
    except Exception as e:
        return {'error': str(e)}
