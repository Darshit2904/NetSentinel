import requests
from urllib.parse import urljoin, urlparse
from datetime import datetime

SECURITY_TXT_PATHS = [
    '/security.txt',
    '/.well-known/security.txt',
]

# Function to fetch the security.txt file
def fetch_security_txt(base_url, path):
    try:
        url = urljoin(base_url, path)
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            return response.text
        elif response.status_code == 404:
            return None
        else:
            return None
    except requests.RequestException:
        return None

# Function to extract relevant fields from the security.txt content
def parse_security_txt(content):
    fields = {
        'Contact': [],
        'Encryption': None,
        'Acknowledgments': None,
        'Policy': None,
        'Hiring': None,
        'Expires': None
    }

    # Split by lines and search for relevant fields
    lines = content.splitlines()
    for line in lines:
        line = line.strip()
        if line.startswith('Contact:'):
            contact = line.split(':', 1)[1].strip()
            fields['Contact'].append(contact)
        elif line.startswith('Encryption:'):
            fields['Encryption'] = line.split(':', 1)[1].strip()
        elif line.startswith('Acknowledgments:'):
            fields['Acknowledgments'] = line.split(':', 1)[1].strip()
        elif line.startswith('Policy:'):
            fields['Policy'] = line.split(':', 1)[1].strip()
        elif line.startswith('Hiring:'):
            fields['Hiring'] = line.split(':', 1)[1].strip()
        elif line.startswith('Expires:'):
            expires_raw = line.split(':', 1)[1].strip()
            fields['Expires'] = format_expiry_date(expires_raw)

    return fields

# Function to format the 'Expires' date
def format_expiry_date(expires_raw):
    try:
        # Handle 'Z' or 'z' at the end of the date string (UTC)
        if expires_raw.endswith('z'):
            expires_raw = expires_raw.replace('z', 'Z')
        expires_date = datetime.strptime(expires_raw, "%Y-%m-%dT%H:%M:%S%z")
        return expires_date.strftime("%B %d, %Y, %I:%M %p UTC")
    except ValueError:
        return expires_raw  # Return as-is if it can't be parsed

# Handler to fetch and parse the security.txt file
def handler(url_or_ip):
    base_url = f"https://{url_or_ip}" if not urlparse(url_or_ip).scheme else url_or_ip
    base_url = base_url.rstrip('/')

    for path in SECURITY_TXT_PATHS:
        result = fetch_security_txt(base_url, path)
        if result is not None:
            parsed_data = parse_security_txt(result)
            return {'isPresent': True, 'fields': parsed_data}

    return {'isPresent': False}

# Display function to show the parsed security.txt fields
def display_security_txt(security_data):
    if security_data['isPresent']:
        print("Security.txt Content:")
        fields = security_data['fields']
        for key, value in fields.items():
            if isinstance(value, list):
                for item in value:
                    print(f"{key}: {item}")
            else:
                print(f"{key}: {value if value else 'Not Provided'}")
    else:
        print("No security.txt file found.")

# # Main execution
# if __name__ == "__main__":
#     # Example usage
#     website_url = "https://www.Google.com"
#     security_data = handler(website_url)
#     display_security_txt(security_data)
