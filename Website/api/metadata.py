import requests
from bs4 import BeautifulSoup

def fetch_metadata(url):
    if not url.startswith('http://') and not url.startswith('https://'):
        url = 'http://' + url
    
    try:
        response = requests.get(url)
        response.raise_for_status()
        html = response.text
        soup = BeautifulSoup(html, 'html.parser')

        metadata = {
            # Basic meta tags
            'title': soup.title.string if soup.title else None,
            'description': soup.find('meta', {'name': 'description'})['content'] if soup.find('meta', {'name': 'description'}) else None,
            'keywords': soup.find('meta', {'name': 'keywords'})['content'] if soup.find('meta', {'name': 'keywords'}) else None,
            'canonicalUrl': soup.find('link', {'rel': 'canonical'})['href'] if soup.find('link', {'rel': 'canonical'}) else None,

            # OpenGraph Protocol
            'ogTitle': soup.find('meta', {'property': 'og:title'})['content'] if soup.find('meta', {'property': 'og:title'}) else None,
            'ogType': soup.find('meta', {'property': 'og:type'})['content'] if soup.find('meta', {'property': 'og:type'}) else None,
            'ogImage': soup.find('meta', {'property': 'og:image'})['content'] if soup.find('meta', {'property': 'og:image'}) else None,
            'ogUrl': soup.find('meta', {'property': 'og:url'})['content'] if soup.find('meta', {'property': 'og:url'}) else None,
            'ogDescription': soup.find('meta', {'property': 'og:description'})['content'] if soup.find('meta', {'property': 'og:description'}) else None,
            'ogSiteName': soup.find('meta', {'property': 'og:site_name'})['content'] if soup.find('meta', {'property': 'og:site_name'}) else None,

            # Twitter Cards
            'twitterCard': soup.find('meta', {'name': 'twitter:card'})['content'] if soup.find('meta', {'name': 'twitter:card'}) else None,
            'twitterSite': soup.find('meta', {'name': 'twitter:site'})['content'] if soup.find('meta', {'name': 'twitter:site'}) else None,
            'twitterCreator': soup.find('meta', {'name': 'twitter:creator'})['content'] if soup.find('meta', {'name': 'twitter:creator'}) else None,
            'twitterTitle': soup.find('meta', {'name': 'twitter:title'})['content'] if soup.find('meta', {'name': 'twitter:title'}) else None,
            'twitterDescription': soup.find('meta', {'name': 'twitter:description'})['content'] if soup.find('meta', {'name': 'twitter:description'}) else None,
            'twitterImage': soup.find('meta', {'name': 'twitter:image'})['content'] if soup.find('meta', {'name': 'twitter:image'}) else None,

            # Misc
            'themeColor': soup.find('meta', {'name': 'theme-color'})['content'] if soup.find('meta', {'name': 'theme-color'}) else None,
            'robots': soup.find('meta', {'name': 'robots'})['content'] if soup.find('meta', {'name': 'robots'}) else None,
            'googlebot': soup.find('meta', {'name': 'googlebot'})['content'] if soup.find('meta', {'name': 'googlebot'}) else None,
            'generator': soup.find('meta', {'name': 'generator'})['content'] if soup.find('meta', {'name': 'generator'}) else None,
            'viewport': soup.find('meta', {'name': 'viewport'})['content'] if soup.find('meta', {'name': 'viewport'}) else None,
            'author': soup.find('meta', {'name': 'author'})['content'] if soup.find('meta', {'name': 'author'}) else None,
            'publisher': soup.find('link', {'rel': 'publisher'})['href'] if soup.find('link', {'rel': 'publisher'}) else None,
            'favicon': soup.find('link', {'rel': 'icon'})['href'] if soup.find('link', {'rel': 'icon'}) else None,
        }

        if not any(metadata.values()):
            return {'skipped': 'No metadata found'}
        
        return metadata

    except requests.RequestException as e:
        return {'error': 'Failed fetching data', 'details': str(e)}

# if __name__ == "__main__":
#     # Example usage
#     website_url = "https://www.cricbuzz.com"
#     Result = fetch_metadata(website_url)
#     print(Result)
