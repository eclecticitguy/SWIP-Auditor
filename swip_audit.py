import requests
import xml.etree.ElementTree as ET
from collections import namedtuple

cenicBlocks = ['137.164.0.0/16', '205.154.0.0/16']
swipEntry = namedtuple('swipEntry', ['Subnet', 'Name'])
listOfNetNames = []
listOfSwipEntries = []


def sortAddresses(address):
    return address.Subnet

# Gather list of ARIN NET-ID's from each CENIC parent block
for address in cenicBlocks:
    resp = requests.get('http://whois.arin.net/rest/cidr/%s/more' % address)
    tree = ET.fromstring(resp.content)

    for child in tree.iter('{http://www.arin.net/whoisrws/core/v1}netRef'):
        handle = child.get('handle')

        if handle not in listOfNetNames:
            listOfNetNames.append(handle)

# Using list of ARIN NET-ID's, parse through each NET-ID and determine organization or customer name. From there,
# parse through one or more netBlock entries to determine starting IP address and CIDR length
for address in listOfNetNames:
    resp = requests.get('http://whois.arin.net/rest/net/%s' % address)
    tree = ET.fromstring(resp.content)

    orgName = tree.find('{http://www.arin.net/whoisrws/core/v1}orgRef')
    custName = tree.find('{http://www.arin.net/whoisrws/core/v1}customerRef')

    if orgName is not None:
        name = orgName.get("name")
    elif custName is not None:
        name = custName.get("name")
    else:
        name = "Unknown name"

    for netRoot in tree.findall('{http://www.arin.net/whoisrws/core/v1}netBlocks/'
                                '{http://www.arin.net/whoisrws/core/v1}netBlock'):

        startAddress = netRoot.find('{http://www.arin.net/whoisrws/core/v1}startAddress')
        cidrLength = netRoot.find('{http://www.arin.net/whoisrws/core/v1}cidrLength')
        swe = swipEntry(startAddress.text + '/' + cidrLength.text, name)
        listOfSwipEntries.append(swe)

# Print list of SWIP'd subnets, along with the organization or customer name
for entry in sorted(listOfSwipEntries, key=sortAddresses):
    print entry.Subnet, entry.Name