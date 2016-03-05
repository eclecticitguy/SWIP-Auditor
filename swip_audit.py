import requests
import xml.etree.ElementTree as ET

cenicBlocks = ['137.164.0.0/16', '205.154.0.0/16', '198.188.0.0/16', '198.189.0.0/16']
listOfNetNames = []


for address in cenicBlocks:
    resp = requests.get('http://whois.arin.net/rest/cidr/%s/more' % address)
    tree = ET.fromstring(resp.content)

    for child in tree.iter('{http://www.arin.net/whoisrws/core/v1}netRef'):
        handle = child.get('handle')

        if handle not in listOfNetNames:
            print ("Item not in list.  Adding " + handle)
            listOfNetNames.append(handle)


for address in listOfNetNames:
    resp = requests.get('http://whois.arin.net/rest/net/%s' % address)
    tree = ET.fromstring(resp.content)

    for netRoot in tree.findall('{http://www.arin.net/whoisrws/core/v1}netBlocks/'
                                '{http://www.arin.net/whoisrws/core/v1}netBlock'):

        startAddress = netRoot.find('{http://www.arin.net/whoisrws/core/v1}startAddress')
        cidrLength = netRoot.find('{http://www.arin.net/whoisrws/core/v1}cidrLength')
        print (startAddress.text + '/' + cidrLength.text)