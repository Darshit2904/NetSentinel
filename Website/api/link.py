import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin

def analyze_links(url):
    response = requests.get(url)
    html = response.text
    soup = BeautifulSoup(html, 'html.parser')

    internal_links_map = {}
    external_links_map = {}

  
    for link in soup.find_all('a', href=True):
        href = link.get('href')
        absolute_url = urljoin(url, href)

       
        if absolute_url.startswith(url):
            internal_links_map[absolute_url] = internal_links_map.get(absolute_url, 0) + 1
        elif href.startswith('http://') or href.startswith('https://'):
            external_links_map[absolute_url] = external_links_map.get(absolute_url, 0) + 1

    
    internal_links = sorted(internal_links_map.keys(), key=lambda k: internal_links_map[k], reverse=True)
    external_links = sorted(external_links_map.keys(), key=lambda k: external_links_map[k], reverse=True)

   
    if not internal_links and not external_links:
        return {
            'skipped': 'No internal or external links found. '
                       'This may be due to the website being dynamically rendered, using a client-side framework (like React), and without SSR enabled. '
                       'That would mean that the static HTML returned from the HTTP request doesn\'t contain any meaningful content for analysis. '
                       'You can rectify this by using a headless browser to render the page instead.'
        }

    return {'internal': internal_links, 'external': external_links}
