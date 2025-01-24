import requests
import xml.etree.ElementTree as ET

class handle_sitemap_check:
    def __init__(self, hard_timeout=5):
        self.hard_timeout = hard_timeout

    def get_sitemap(self, url):
        sitemap_url = f"{url}/sitemap.xml"

        try:
            sitemap_res = requests.get(sitemap_url, timeout=self.hard_timeout)

            if sitemap_res.status_code == 200:
                return self.parse_sitemap(sitemap_res.content)

        except requests.exceptions.HTTPError as http_err:
            if http_err.response.status_code == 404:
                return self.fetch_from_robots(url)

        except requests.exceptions.Timeout:
            return {"error": f"Request timed out after {self.hard_timeout} seconds"}
        except requests.exceptions.RequestException as req_err:
            return {"error": str(req_err)}

        return {"skipped": "No sitemap found"}

    def fetch_from_robots(self, url):
        try:
            robots_res = requests.get(f"{url}/robots.txt", timeout=self.hard_timeout)
            robots_txt = robots_res.text.splitlines()

            sitemap_url = None
            for line in robots_txt:
                if line.lower().startswith('sitemap:'):
                    sitemap_url = line.split(' ')[1].strip()
                    break

            if sitemap_url:
                sitemap_res = requests.get(sitemap_url, timeout=self.hard_timeout)
                return self.parse_sitemap(sitemap_res.content)

        except requests.exceptions.RequestException as req_err:
            return {"error": str(req_err)}

        return {"skipped": "No sitemap found"}

    def parse_sitemap(self, xml_content):
        try:
            root = ET.fromstring(xml_content)
            sitemap_dict = self.xml_to_dict(root)
            return sitemap_dict
        except ET.ParseError as parse_err:
            return {"error": f"Failed to parse XML: {str(parse_err)}"}

    def xml_to_dict(self, elem):
        return {elem.tag: [self.xml_to_dict(child) for child in elem] or elem.text}
