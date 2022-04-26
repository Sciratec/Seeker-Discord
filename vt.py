from json import loads
from dotenv import load_dotenv
from os import getenv
import requests

load_dotenv()
VT_TOKEN = getenv('VT_TOKEN')

def virustotal(id):
    malNames = []
    iocUrls = []
    iocIP = []
    contextTuple = []
    iocDomains = []

    headers = {
        "Accept": "application/json",
        "x-apikey": VT_TOKEN
    }

    fileAnalysis = f"https://www.virustotal.com/api/v3/files/{id}"
    relationURLS = f"https://www.virustotal.com/api/v3/files/{id}/contacted_urls"
    relationIP = f"https://www.virustotal.com/api/v3/files/{id}/relationships/contacted_ips"
    relationDomains = f"https://www.virustotal.com/api/v3/files/{id}/relationships/contacted_domains"
    
    
    vtURLS = requests.get(relationURLS, headers=headers)
    vtIPS = requests.get(relationIP, headers=headers)
    vtFile = requests.get(fileAnalysis, headers=headers)
    vtDomains = requests.get(relationDomains, headers=headers)
    
    vtFilesJson = loads(vtFile.text)
    vtURLJson = loads(vtURLS.text)
    vtIPJson = loads(vtIPS.text)
    vtDomainJson = loads(vtDomains.text)

    if 'error' in vtFilesJson:
        return vtFilesJson['error']['code']

    vtFileEntry = vtFilesJson['data']['attributes']
    vtURLEntry = vtURLJson['data']
    vtIPEntry = vtIPJson['data']
    vtDomainEntry = vtDomainJson['data']
    
    # for object in vtURLEntry:
    #     if 'url' in object['attributes']:
    #         iocURL = object['attributes']['url']
    #         iocURLSanitized = iocURL.replace(".", "[.]").replace(":", "[:]")
    #         if 'crowdsourced_context' in object['attributes']:
    #             for context in object['attributes']['crowdsourced_context']:
    #                 contextTuple.append((iocURLSanitized, context['detail']))
    #         else:
    #             iocUrls.append(iocURLSanitized)

    if 'sandbox_verdicts' in vtFileEntry:
        sandBox = vtFileEntry['sandbox_verdicts']
        for key, value in sandBox.items():
            if 'malware_names' in value.keys():
                for values in value['malware_names']:
                    malNames.append(values)
    if vtIPEntry:
        for ip in vtIPEntry:
            iocIPS = ip['id']
            iocSanitized = iocIPS.replace(".", "[.]")
            iocIP.append(iocSanitized)
    
    if vtDomainEntry:
        for domain in vtDomainEntry:
            iocDomain = domain['id']
            iocSanitized = iocDomain.replace(".", "[.]")
            iocDomains.append(iocSanitized)

            
    return malNames, iocUrls, iocIP, contextTuple, iocDomains