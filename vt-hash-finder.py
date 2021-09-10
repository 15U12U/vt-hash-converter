#!/usr/bin/python3
# created by 15U12U

import csv
import sys
import requests
import json
import time

# creating a csv file to save results
header = ['input_hash', 'names', 'md5', 'sha1', 'sha256']

with open('hashes.csv', 'w', encoding='UTF8') as csv_file:
    writer = csv.writer(csv_file)

    # writing the header
    writer.writerow(header)

    csv_file.close()

# api-endpoint
api_url = "https://www.virustotal.com/api/v3/search"

# Request Headers
request_headers = {'x-apikey': str(sys.argv[1])}

# defining a dict for the parameters to be sent to the API
with open(sys.argv[2], "r") as file:
    hash_list=file.read().splitlines()

    file.close()

    for hash in hash_list:

        # setting the parameter
        request_params = {'query': hash}

        # sending get request and saving the response as 'response' object
        response = requests.get(url = api_url, params = request_params, headers = request_headers)


        if (response.status_code == 200):
            json_data = response.json()
        
            if json_data['data']:

                md5 = json_data['data'][0]['attributes']['md5']
                sha1 = json_data['data'][0]['attributes']['sha1']
                sha256 = json_data['data'][0]['attributes']['sha256']
                names = json_data['data'][0]['attributes']['names']

                data = [hash, names, md5, sha1, sha256]

                with open('hashes.csv', 'a', encoding='UTF8') as csv_file:
                    writer = csv.writer(csv_file)

                    # writing the output to a new row
                    writer.writerow(data)

                    csv_file.close()
            
                time.sleep(15)
            else:

                data = [hash, 'N/A', 'N/A', 'N/A', 'N/A']

                with open('hashes.csv', 'a', encoding='UTF8') as csv_file:
                    writer = csv.writer(csv_file)

                    # writing the output to a new row
                    writer.writerow(data)

                    csv_file.close()
                
        elif (response.status_code == 400):
            print("Please verify the hash in line", hash_list.index(hash)+1, "of the input file")
        elif (response.status_code == 401):
            print("Please insert a valid api key!")
            exit(1)

exit(0)
