import http.client
import json
import secrets_file
import hmac
import hashlib
import csv
import time
import tabulate as tbl
from datetime import datetime, timezone

# Get current UTC time
utcNow = datetime.now(timezone.utc)
# Format the UTC time in HTTP format
utcTime = utcNow.strftime("%a, %d %b %Y %H:%M:%S GMT")
authHmacSha1 = hmac.new(secrets_file.secretKey.encode('utf-8'), utcTime.encode('utf-8'), hashlib.sha1).hexdigest()
headers = {
'Content-Type': 'application/json',
'x-dnsme-apiKey': secrets_file.apiKey,
'x-dnsme-hmac': authHmacSha1,
'x-dnsme-requestDate': utcTime,
}

baseUrl = 'api.dnsmadeeasy.com'
conn = http.client.HTTPSConnection("api.dnsmadeeasy.com")
boundary = ''
payload = ''

csvFilePath = "./GetDomainsResults.csv"
tableData = []

def make_api_request(method, url, headers=None, body=None):
   # Get current UTC time
    utcNow = datetime.now(timezone.utc)
    # Format the UTC time in HTTP format
    utcTime = utcNow.strftime("%a, %d %b %Y %H:%M:%S GMT")
    authHmacSha1 = hmac.new(secrets_file.secretKey.encode('utf-8'), utcTime.encode('utf-8'), hashlib.sha1).hexdigest()
    headers = {
    'Content-Type': 'application/json',
    'x-dnsme-apiKey': secrets_file.apiKey,
    'x-dnsme-hmac': authHmacSha1,
    'x-dnsme-requestDate': utcTime,
    }
    conn.request(method, url, body, headers)
    response = conn.getresponse()
    data = response.read()
    conn.close()
    return response, data

zonesResponse, zonesData = make_api_request('GET', '/V2.0/dns/managed/', headers)
zonesData = json.loads(zonesData)

with open(csvFilePath, mode='w', newline='') as csv_file:
    # Create a CSV writer object
    csvWriter = csv.writer(csv_file)
    # Write header row
    csvWriter.writerow(['Zone', 'Record Name', 'Type', 'Value'])

if zonesResponse.status == 200:
    # Loop through each zone and retrieve its records
    for zone in zonesData['data']:
        zoneID = zone['id']
        zoneName = zone['name']
        
        # Get records for the current zone
        recordsResponse, recordsData = make_api_request('GET', f'/V2.0/dns/managed/{zoneID}/records/', headers=headers)
        recordsData = json.loads(recordsData)
        if recordsResponse.status == 200:
            for record in recordsData['data']:
                tableData.append([zoneName, record['name'], record['type'], record['value']])
                with open(csvFilePath, 'w', newline='') as csvFile:
                    csvWriter = csv.writer(csvFile)
                    csvWriter.writerow([zoneName, record['name'], record['type'], record['value']])
                    csvWriter.writerows(tableData)
                print(tbl.tabulate(tableData, headers=['Zone', 'Record Name', 'Type', 'Value']))
                time.sleep(.5)

        else:
             print(f"Failed to retrieve records for zone {zoneName}.")
else:
    print(f"Failed to retrieve zones.")

        
# # Check if response is JSON and log formatted JSON
# try:
#     json_response = json.loads(data.decode("utf-8"))
#     formatted_json = json.dumps(json_response, indent=4)
#     print(formatted_json)
# except json.JSONDecodeError:
#     # If the response is not JSON, print as is.
#     print(data.decode("utf-8"))
