import requests
import xml.etree.ElementTree as ET

resp = requests.get('http://whois.arin.net/rest/net/NET-198-188-17-0-1')
tree = ET.fromstring(resp.content)
orgName = tree.find('{http://www.arin.net/whoisrws/core/v1}orgRef')
print orgName.get('name')