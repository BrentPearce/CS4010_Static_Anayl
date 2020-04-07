import hashlib
import requests
from pathlib import Path
import pycurl
from io import BytesIO
import json
import time


def uploadForVTScan(exe_path):
    #################### Find out the file size ###########################
    file = Path(exe_path)

    fileSize = file.stat().st_size

    #################### If it is smaller than 32 MB go ahead, otherwise terminate #################

    if fileSize >= 33554432:  # 32 MB
        print("file is too large, file must be smaller than 32MB")
        return

    else:
        print("File is smaller than 32 MB :) \n")
        fileScanUrl = 'https://www.virustotal.com/vtapi/v2/file/scan'
        apiKey = '041fb89143ff2506c8077674f4dc15e6ce0a16d74f76aabaa1945fee060acf91'
        params = {'apikey': apiKey}

        files = {'file': (exe_path, open(exe_path, 'rb'))}
        #################### Ensure the file was successfully uploaded, if not print error message and quit.
        uploadResponse = requests.post(fileScanUrl, files=files, params=params)
        uploadStatCode = uploadResponse.status_code

        #################### File was uploaded, get file upload ID.
        if uploadStatCode == 200:
            # get scan ID
            scanID = uploadResponse.json()['resource']
            print("The file was uploaded successfully. If you think it may have already been scanned previously "
                  "\nfeel free to request the report now. Otherwise wait a couple of minutes for analysis to finish.")
            return scanID


        #################### Some sort of error, if possible print error message, then end program.
        elif uploadStatCode == 429:
            print("Too many requests to virus total API. Limited to 4 requests per minute."
                  "\nOr you may have exceeded daily the daily or weekly API limits")
            return None
        elif uploadStatCode == 401:
            print("Authentication Error: Is the provided api key correct and activated?\n")
            return None

        else:
            print("There was an error uploading the file to Virus total. Error: " + uploadStatCode + "\n")
            return None

def getVTFileReport(resource):
    if resource == None:
        print("File has not been uploaded to Virus Total")

    else:
        apiKey = '041fb89143ff2506c8077674f4dc15e6ce0a16d74f76aabaa1945fee060acf91'
        # use upload ID to get the file analysis.
        reportUrl = 'https://www.virustotal.com/vtapi/v2/file/report'

        params = {'apikey': apiKey, 'resource': resource}

        fileReport = requests.get(reportUrl, params=params)
        fraction = [str(fileReport.json()['positives']), str(fileReport.json()['total'])]
        print("Detected by " + fraction[0]+ " of " + fraction[1] + " total anti-malware scans")

def printPositiveScans():
    return None

def jprint(obj):
    # create a formatted string of the Python JSON object
    text = json.dumps(obj, sort_keys=False, indent=2)
    print(text)


path = input("Please enter the file to analyze\n")
id = uploadForVTScan(path)
#print("going to sleep a little bit")
#time.sleep(30)
#print("30 seconds")
#time.sleep(30)
#print("waking up:")
getVTFileReport(id)

