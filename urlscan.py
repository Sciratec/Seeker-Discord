from email import header
import requests
from dotenv import load_dotenv
from os import getenv
from re import search
from json import loads


load_dotenv()
URLSCAN_TOKEN = getenv('URLSCAN_TOKEN')

def urlSearch(artifact):
    endpoint = 'https://urlscan.io/api/v1/search/?q='

    headers = {'API-Key':URLSCAN_TOKEN,'Content-Type':'application/json'}

    stripped_artifact = artifact.strip("/")

    search_domains = requests.get(f'{endpoint}page.domain:{stripped_artifact}', headers=headers)
    payload = loads(search_domains.text)

    times_seen = payload['total']
    recent_seen = payload['results'][0]['task']['time']
    has_more =  payload['has_more']
    time_split = recent_seen.split("T")
    recent_screenshot = payload['results'][0]['screenshot']

    return times_seen, time_split, has_more,recent_screenshot


        # if payload['total'] == 10000 and payload['has_more'] == True:
	    #     print("Seen more than 10000 times")
	    #     print(f"Time last seen on urlscan was {payload['results'][0]['task']['time']}")
        # else:
	    #     time_split = payload['results'][0]['task']['time'].split("T")
	    #     print(f"Domain has been seen {payload['total']} times")
	    #     print(f"Time last seen on urlscan was {time_split[0]}"

def urlScan(artifact):
    pass