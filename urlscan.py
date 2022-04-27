import requests
from dotenv import load_dotenv
from os import getenv
from json import loads, dumps
from time import sleep


load_dotenv()
URLSCAN_TOKEN = getenv('URLSCAN_TOKEN')

def urlSearch(artifact):
    endpoint = 'https://urlscan.io/api/v1/search/?q='

    headers = {'API-Key':URLSCAN_TOKEN,'Content-Type':'application/json'}

    stripped_artifact = artifact.strip("/")

    search_domains = requests.get(f'{endpoint}page.domain:{stripped_artifact}', headers=headers)
    payload = loads(search_domains.text)

    times_seen = payload['total']
    recent_seen = None
    time_split = None
    has_more = None
    recent_screenshot = None

    if payload['results']:
        recent_seen = payload['results'][0]['task']['time']
        recent_screenshot = payload['results'][0]['screenshot']
        time_split = recent_seen.split("T")
        has_more =  payload['has_more']
    else:
        recent_seen = None
        recent_screenshot = None
        time_split = None

    return times_seen, time_split, has_more,recent_screenshot

def urlScan(artifact):
    error = None
    filename = None
    filesize = None
    mime_description = None
    file_hash = None
    scanned_results = None

    headers = {'API-Key':URLSCAN_TOKEN,'Content-Type':'application/json'}

    data = {"url": artifact, "visibility": "public"}

    scan_url = requests.post('https://urlscan.io/api/v1/scan/',headers=headers, data=dumps(data))

    sleep(30)

    payload = loads(scan_url.text)
    print(payload)

    if payload['message'] == 'Submission successful':
        sleep(10)
        scan_results = requests.get(payload['api'], headers=headers)
        scanned_results = loads(scan_results.text)
    else:
        error = payload['message']
        return error
    
    report_url = scanned_results['task']['reportURL']
    screenshot = scanned_results['task']['screenshotURL']

    overall_verdict = scanned_results['verdicts']['overall']['malicious']
    urlscan_verdict = scanned_results['verdicts']['urlscan']['malicious']
    engines_verdict = scanned_results['verdicts']['engines']['malicious']
    community_verdict = scanned_results['verdicts']['community']['malicious']


    if 'download' in scanned_results['meta']['processors']:
        print("Made it here!")
        filename = scanned_results['meta']['processors']['download']['data'][0]['filename']
        filesize = scanned_results['meta']['processors']['download']['data'][0]['filesize']
        mime_description = scanned_results['meta']['processors']['download']['data'][0]['mimeDescription']
        file_hash = scanned_results['meta']['processors']['download']['data'][0]['sha256']

    print(filename, filesize, mime_description, file_hash)

    return error, report_url, screenshot, overall_verdict, urlscan_verdict, engines_verdict, community_verdict, filename, filesize, mime_description, file_hash

    



