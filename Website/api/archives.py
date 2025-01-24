import requests
from datetime import datetime


def convert_timestamp_to_date(timestamp):
    year = int(timestamp[:4])
    month = int(timestamp[4:6])
    day = int(timestamp[6:8])
    hour = int(timestamp[8:10])
    minute = int(timestamp[10:12])
    second = int(timestamp[12:14])
    return datetime(year, month, day, hour, minute, second)


def count_page_changes(results):
    prev_digest = None
    change_count = 0
    for result in results:
        if result[2] != prev_digest:
            prev_digest = result[2]
            change_count += 1
    return change_count - 1


def get_average_page_size(scans):
    total_size = sum(int(scan[3]) for scan in scans)
    return round(total_size / len(scans))


def get_scan_frequency(first_scan, last_scan, total_scans, change_count):
    day_factor = (last_scan - first_scan).total_seconds() / (60 * 60 * 24)
    days_between_scans = round(day_factor / total_scans, 2)
    days_between_changes = round(day_factor / change_count, 2)
    scans_per_day = round((total_scans - 1) / day_factor, 2)
    changes_per_day = round(change_count / day_factor, 2)
    return {
        'days_between_scans': days_between_scans,
        'days_between_changes': days_between_changes,
        'scans_per_day': scans_per_day,
        'changes_per_day': changes_per_day,
    }


def fetch_wayback_data(url):
    cdx_url = f'https://web.archive.org/cdx/search/cdx?url={url}&output=json&fl=timestamp,statuscode,digest,length,offset'

    try:
        response = requests.get(cdx_url)
        data = response.json()

        if not data or len(data) <= 1:
            return {'skipped': 'Site has never been archived via the Wayback Machine'}

        data.pop(0) 
        first_scan = convert_timestamp_to_date(data[0][0])
        last_scan = convert_timestamp_to_date(data[-1][0])
        total_scans = len(data)
        change_count = count_page_changes(data)

        return {
            'first_scan': first_scan,
            'last_scan': last_scan,
            'total_scans': total_scans,
            'change_count': change_count,
            'average_page_size': get_average_page_size(data),
            'scan_frequency': get_scan_frequency(first_scan, last_scan, total_scans, change_count),
            'scans': data,
            'scan_url': url,
        }
    except Exception as e:
        return {'error': f'Error fetching Wayback data: {str(e)}'}


# print(fetch_wayback_data('https://www.cricbuzz.com'))