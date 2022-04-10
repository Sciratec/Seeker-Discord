import requests
from dotenv import load_dotenv
from os import getenv
from json import loads

load_dotenv()
HT_TOKEN = getenv('HATCHING_TOKEN')


def hatchingTriage(id):

    headers = {
        'Authorization': f"Bearer {HT_TOKEN}",
    }
    params = (
        ('query', f'sha256:{id}'),
    )
    hashSearch = requests.get('https://api.tria.ge/v0/search',
                              headers=headers, params=params)

    searchJson = loads(hashSearch.text)

    malID = ""

    if "error" not in searchJson:
        malID = searchJson['data'][0]['id']

    malAnalysis = requests.get(
        f'https://api.tria.ge/v0/samples/{malID}/overview.json', headers=headers)

    json_object = loads(malAnalysis.text)

    c2s = []
    cncURLs = []
    iocURLs = []
    iocIPS = []
    signatures = []


    if 'extracted' in json_object:
        for extract in json_object['extracted']:
            if 'config' in extract:
                if "c2" in extract['config']:
                    rule = extract['config']['rule']
                    for c2 in extract['config']['c2']:
                        tuplei = []
                        tuplei.append(rule)
                        c2Sanitized = c2.replace(".", "[.]").replace(':', "[:]")
                        tuplei.append(c2Sanitized)
                        c2s.append(tuplei)
                if 'attr' in extract['config']:
                    rule = extract['config']['rule']
                    if 'url4cnc' in extract['config']['attr']:
                        for cncURL in extract['config']['attr']['url4cnc']:
                            tuplei = []
                            tuplei.append(rule)
                            cncURLSanitized = cncURL.replace(".", "[.]").replace(':', "[:]")
                            tuplei.append(cncURLSanitized)
                            cncURLs.append(tuplei)

    if 'targets' in json_object:
        for target in json_object['targets']:
            if 'iocs' in target:
                if 'urls' in target['iocs']:
                    for url in target['iocs']['urls']:
                        iocURLsSanitized = url.replace(".", "[.]").replace(':', "[:]")
                        iocURLs.append(iocURLsSanitized)
                if 'ips' in target['iocs']:
                    for ip in target['iocs']['ips']:
                        ipSanitized = ip.replace(".", "[.]")
                        iocIPS.append(ipSanitized)
            if 'signatures' in target:
                for signature in target['signatures']:
                    sigList = []
                    sigList.append(signature['name'])
                    if 'desc' in signature:
                        sigList.append(signature['desc'])
                    signatures.append(sigList)
    
    return c2s, cncURLs, iocURLs, iocIPS, signatures
