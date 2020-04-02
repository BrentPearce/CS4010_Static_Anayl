import pefile


class ReadStrings:

    @staticmethod
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
        pe.close()
