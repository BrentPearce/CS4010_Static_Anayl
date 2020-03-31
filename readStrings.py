import pefile


class ReadStrings:

    @staticmethod
    def read_strings(file):
        pe = pefile.PE(file)
        pe.full_load()
        print("Loaded")
        pe.write("fileinfo.txt")
        print("written")
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
        pe.close()
