import pefile
from lxml import html
import requests
from googlesearch import search


def main():
    try:
        exe_path = input("what is the file path?\n")
        pe = pefile.PE(exe_path)
    except:
        print("file does not exist, try again?")
        main()
    select = "0"
    while select != "99":
        select = input("What would you like to do (use numbers to select)\n1.dump imports\n2.Find imports in a dll\n"
                       "3.Try to define all imports (will most likely fail due to limitations)4.\n4.define an import\n"
                       "5.Dump strings"
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

def dump_dll_imports(pefile):
    dump_dll(pefile)
    name = input("What dll would you like to use?\n")
    for entry in pefile.DIRECTORY_ENTRY_IMPORT:
        dll_name = entry.dll.decode('utf-8')
        if dll_name == name:
            print("[*] " + dll_name + " imports:")
            for func in entry.imports:
                print((func.name.decode('utf-8')))


def dump_imports(pefile):
    for entry in pefile.DIRECTORY_ENTRY_IMPORT:
        dll_name = entry.dll.decode('utf-8')
        print("[*] " + dll_name + " imports:")
        for func in entry.imports:
            print((func.name.decode('utf-8')))

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
    strings = pe.get_resources_strings()
    stuff = pe.get_warnings()
    print(pe.PE_TYPE)
    if len(strings) != 0 or len(stuff) != 0:
        for item in strings:
            print(item)
        # for item in stuff:
        # print(item)
    else:
        print("empty")


main()
