import requests
import zipfile
import io
import csv
import os

FILE_URL = 'https://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip'
TEMP_FILE_PATH = '/tmp/top-1m.csv'

def check_domain_rank(url):
    try:
        domain = url.split('//')[-1].split('/')[0]
        
       
        if not os.path.exists(TEMP_FILE_PATH):
           
            response = requests.get(FILE_URL, stream=True)
            with zipfile.ZipFile(io.BytesIO(response.content)) as zip_ref:
                zip_ref.extractall('/tmp')
        
       
        with open(TEMP_FILE_PATH, mode='r', newline='', encoding='utf-8') as csvfile:
            reader = csv.DictReader(csvfile, fieldnames=['rank', 'domain'])
            for row in reader:
                if row['domain'] == domain:
                    return {
                        'domain': domain,
                        'rank': row['rank'],
                        'isFound': True,
                    }
        
        return {
            'skipped': f'Skipping, as {domain} is not present in the Umbrella top 1M list.',
            'domain': domain,
            'isFound': False,
        }

    except Exception as e:
        return {
            'statusCode': 500,
            'error': str(e)
        }


# if __name__ == "__main__":
#     # Example usage
#     website_url = "https://www.Google.com"
#     result = check_domain_rank(website_url)
#     print(result)
