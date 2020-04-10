import hashlib
import pefile
from lxml import html
import requests
from googlesearch import search
from pathlib import Path


def main():
    try:
        exe_path = input("what is the file path?\n")
        pe = pefile.PE(exe_path)
    except:
        print("file does not exist, try again?")
        main()
    select = "0"
    vtResource = None
    permalink = None
    detected_scans = []
    while select != "99":
        select = input("What would you like to do (use numbers to select)\n1.dump imports\n2.Find imports in a dll\n"
                       "3.Try to define all imports (will most likely fail due to limitations)\n4.define an import\n"
                       "5.Dump strings\n"
                       "6.Upload file to Virus Total\n"
                       "7.Get file report from Virus Total\n"
                       "8.Use the file hash to get the report from Virus Total\n"
                       "9.Output all information to a .txt file"
                       "\n99.exit\n")
        if select == "1":
            dump_imports(pe)
        if select == "2":
            dump_dll_imports(pe)
        if select == "3":
            define_all(pe)
        if select == "4":
            define_import(input("What is the name of the import you wish to define?\n"))
        if select == "5":
            dump_strings(pe)
        if select == "6":
            vtResource = uploadForVTScan(exe_path)
        if select == "7":
            vt_report = getVTFileReport(vtResource)
            vt_string = vt_report[0]
            print(vt_string)
            detected_scans = vt_report[1]
            ###By default the next three lines are commented out to aviod printing a possibly very large amount of info.
            # print("The file was detected with the following scans: \n")
            # for i in detected_scans:
            # i.print_info()

            permalink = vt_report[2]
            print("A more complete scan report can be found at: \n" + permalink + "\n")

        if select == "8":
            hashlib.md5()
            with open(exe_path, 'rb') as file:
                data = file.read()
                hashlib.md5().update(data)
                vtResource = hashlib.md5(data).hexdigest()
            vt_report = getVTFileReport(vtResource)
            vt_string = vt_report[0]
            print(vt_string)
            detected_scans = vt_report[1]
            ###By default the next three lines are commented out to aviod printing a possibly very large amount of info.
            # print("The file was detected with the following scans: \n")
            # for i in detected_scans:
            # i.print_info()

            permalink = vt_report[2]
            print("A more complete scan can be found at: \n" + permalink)
        if select == "9":
            dump_to_txt(exe_path, pe)


def dump_to_txt(path, pfile):
    file = open(path + "report.txt", "w")
    hashlib.md5()
    with open(path, 'rb') as tfile:
        data = tfile.read()
        hashlib.md5().update(data)
        vtResource = hashlib.md5(data).hexdigest()
    for element in getVTFileReport(vtResource)[1]:
        file.writelines(element.print_info())
    file.writelines("\n\nDll functions used:")
    file.writelines(dump_imports(pfile))
    file.writelines("\n\nStrings found:")
    file.writelines(dump_strings(pfile))


def dump_dll_imports(pefile):
    dump_dll(pefile)
    name = input("What dll would you like to use?\n")
    arr = [];
    for entry in pefile.DIRECTORY_ENTRY_IMPORT:
        dll_name = entry.dll.decode('utf-8')
        if dll_name == name:
            print("[*] " + dll_name + " imports:")
            arr.append("[*] " + dll_name + " imports:\n")
            for func in entry.imports:
                print((func.name.decode('utf-8')))
                arr.append((func.name.decode('utf-8')) + "\n")
    return arr


def dump_imports(pefile):
    arr = []
    for entry in pefile.DIRECTORY_ENTRY_IMPORT:
        dll_name = entry.dll.decode('utf-8')
        print("[*] " + dll_name + " imports:\n\n")
        arr.append("[*] " + dll_name + " imports:\n\n")
        for func in entry.imports:
            print((func.name.decode('utf-8')) + "\n")
            arr.append((func.name.decode('utf-8')) + "\n")
    return arr


def dump_dll(pefile):
    print("[*] Listing imported DLLs...")
    for entry in pefile.DIRECTORY_ENTRY_IMPORT:
        print('\t' + entry.dll.decode('utf-8'))


def define_all(pefile):
    print("due to google limiting requests there might be issues with larger files")
    tlds = ["net", "com", "co.in"]
    counter = 0;
    for entry in pefile.DIRECTORY_ENTRY_IMPORT:
        if entry.dll.decode('utf-8') != "MSVCR120.dll" and entry.dll.decode('utf-8') != "MSVCP120.dll":
            for func in entry.imports:
                try:
                    request = 'microsoft.com ' + func.name.decode('utf-8')
                    page = ''
                    for url in search(request, tld="" + tlds[counter], num=1, stop=1, start=0, pause=4):
                        page = url
                    tree = html.fromstring(requests.get(page).content)
                    description = ""
                    if len(tree.xpath('//meta[@name="description"]/@content')) == 1:
                        description = tree.xpath('//meta[@name="description"]/@content').pop()
                    else:
                        if len(tree.xpath('//*[@id="main"]/p[1]/text()[1]')) == 1:
                            description = tree.xpath('//*[@id="main"]/p[1]/text()[1]').pop()
                            if len(tree.xpath('//*[@id="main"]/p[1]/a/strong/text()[1]')) <= 1:
                                description = description + tree.xpath('//*[@id="main"]/p[1]/a/strong/text()[1]').pop()
                        else:
                            description = "sorry no description could be found"
                    print(func.name.decode('utf-8').ljust(30) + ':   ' + description)
                except:
                    print("sorry there was an error, we will just move on.")
                    counter = counter + 1
                    if counter == 3:
                        print("we could not define all the files due to google limitations")
                        return 0


def define_import(name):
    request = 'microsoft.com ' + name
    page = ''
    for url in search(request, tld="com", num=1, stop=1, start=0, pause=1):
        page = url
    tree = html.fromstring(requests.get(page).content)
    description = ""
    if len(tree.xpath('//meta[@name="description"]/@content')) == 1:
        description = tree.xpath('//meta[@name="description"]/@content').pop()
    else:
        if len(tree.xpath('//*[@id="main"]/p[1]/text()[1]')) == 1:
            description = tree.xpath('//*[@id="main"]/p[1]/text()[1]').pop()
            if len(tree.xpath('//*[@id="main"]/p[1]/a/strong/text()[1]')) <= 1:
                description = description + tree.xpath('//*[@id="main"]/p[1]/a/strong/text()[1]').pop()
        else:
            description = "sorry no description could be found"
    print(name + ':   ' + description)


def dump_strings(pefile):
    pefile.full_load()
    strings = pefile.get_resources_strings()
    stuff = pefile.get_warnings()
    arr = [];
    print(pefile.PE_TYPE)
    if len(strings) != 0 or len(stuff) != 0:
        for item in strings:
            print(item)
            arr.append(item + "\n")
        # for item in stuff:
        # print(item)
    else:
        print("empty")
        arr.append("empty")
    return arr


def uploadForVTScan(exe_path):
    #################### Find out the file size ###########################
    file = Path(exe_path)

    fileSize = file.stat().st_size

    #################### If it is smaller than 32 MB go ahead, otherwise terminate #################

    if fileSize >= 33554432:  # 32 MB
        print("file is too large, file must be smaller than 32MB")
        return

    else:
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
                  "\nfeel free to request the report now. Otherwise wait a couple of minutes for the analysis to"
                  "finish, then press option 7.\n")
            return scanID


        #################### Some sort of error, if possible print error message, then end program.
        elif uploadStatCode == 429:
            print("Too many requests to virus total API. Limited to 4 requests per minute."
                  "\nOr you may have exceeded daily the daily or weekly API limits\n")
            return None
        elif uploadStatCode == 401:
            print("Authentication Error: Is the provided api key correct and activated?\n")
            return None

        else:
            print("There was an error uploading the file to Virus total. Error: " + str(uploadStatCode) + "\n")
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
        vtString = "Detected by " + fraction[0] + " of " + fraction[1] + " total anti-malware scans\n"
        fileReport.encoding = 'JSON'
        scans = fileReport.json()['scans']
        detected_scans = []

        for key in scans:
            if scans[key]['detected'] is True:
                version = str(scans[key]['version'])
                result = str(scans[key]['result'])
                update = str(scans[key]['update'])
                positive_scan = VT_Scans(key, version, result, update)
                detected_scans.append(positive_scan)

        permalink = fileReport.json()['permalink']
        vt_report = [vtString, detected_scans, permalink]
        return vt_report


class VT_Scans:
    def __init__(self, name, version, result, update):
        self.name = name
        self.result = result
        self.version = version
        self.update = update

    def print_info(self):
        arr = []
        print(self.name + ":\n")
        arr.append(self.name + ":\n")
        print("\tfound with version, update: " + self.version + ", " + self.update + "\n")
        arr.append("\tfound with version, update: " + self.version + ", " + self.update + "\n")
        print("\tscan result: " + self.result + "\n")
        arr.append("\tscan result: " + self.result + "\n")
        return arr


main()
