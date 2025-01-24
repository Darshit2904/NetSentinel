import requests
from urllib.parse import urlparse
import re

def parse_robots_txt(content):
    lines = content.split('\n')
    rules = {}
    current_user_agent = None

    for line in lines:
        line = line.strip()  # Removes leading and trailing whitespaces

        # Skip empty lines or comments
        if not line or line.startswith('#'):
            continue

        # Match User-agent directive
        user_agent_match = re.match(r'^(User-agent):\s*(\S+)$', line, re.IGNORECASE)
        if user_agent_match:
            current_user_agent = user_agent_match.group(2)
            rules[current_user_agent] = []  # Initialize rules for this user agent
            continue

        # Match Allow or Disallow directives
        if current_user_agent:  # Only add rules if a user-agent has been found
            rule_match = re.match(r'^(Allow|Disallow):\s*(.+)$', line, re.IGNORECASE)
            if rule_match:
                rule = {
                    'lbl': rule_match.group(1),
                    'val': rule_match.group(2),
                }
                rules[current_user_agent].append(rule)

    return rules

def handler(url_or_ip):
    try:
        parsed_url = urlparse(url_or_ip)
        if not parsed_url.scheme or not parsed_url.hostname:
            raise ValueError('Invalid URL provided')
    except Exception as e:
        return {
            'statusCode': 400,
            'body': {'error': 'Invalid URL query parameter'}
        }

    robots_url = f"{parsed_url.scheme}://{parsed_url.hostname}/robots.txt"

    try:
        response = requests.get(robots_url)
        response.raise_for_status()  # Raise an error for bad responses

        if response.status_code == 200:
            print("Raw robots.txt Content:")
            print(response.text)  # Print raw content for debugging
            
            parsed_data = parse_robots_txt(response.text)
            print(f"Parsed Data: {parsed_data}")  # Debugging line
            
            return {'statusCode': 200, 'body': parsed_data}
        else:
            return {
                'statusCode': response.status_code,
                'body': {'error': 'Failed to fetch robots.txt', 'statusCode': response.status_code}
            }
    except requests.RequestException as e:
        return {
            'statusCode': 500,
            'body': {'error': f'Error fetching robots.txt: {str(e)}'}
        }

def display_rules(rules):
    if 'statusCode' in rules:
        print(f"Status Code: {rules['statusCode']}")
        if 'body' in rules and 'error' in rules['body']:
            print(f"Error: {rules['body'].get('error', 'Unknown error')}")
            return
        elif 'body' in rules and not rules['body']:
            print("No relevant rules found in robots.txt.")
            return

    for user_agent, directives in rules['body'].items():
        print(f"User-agent: {user_agent}")
        for directive in directives:
            print(f" - {directive['lbl']}: {directive['val']}")
        # print()  

# if __name__ == "__main__":
#     # Example usage
#     website_url = "https://www.vupune.ac.in"
#     rules = handler(website_url)
#     display_rules(rules)
