import pefile

print('\n\nARCHIVO 1\n\n')

pe = pefile.PE('MALWR/sample_qwrty_dk2')

print('SECCIONES')
for section in pe.sections:
    print('\t', section.Name, hex(section.VirtualAddress), hex(section.Misc_VirtualSize), section.SizeOfRawData)


for entry in pe.DIRECTORY_ENTRY_IMPORT:
    print('LLAMADAS A DLL')
    print('\t', entry.dll)
    print('\t\tLLAMADAS A FUNCIONES ')
    for function in entry.imports:
        print('\t\t\t', function.name)

print('TimeDateStamp: ' + pe.FILE_HEADER.dump_dict()['TimeDateStamp']['Value'].split('[')[1][:-1])
print('TimeDateStamp: ' + hex(pe.FILE_HEADER.TimeDateStamp))


print('\n\nARCHIVO 2\n\n')
pe2 = pefile.PE('MALWR/sample_vg655_25th.exe')

print('SECCIONES')
for section in pe2.sections:
    print('\t', section.Name, hex(section.VirtualAddress), hex(section.Misc_VirtualSize), section.SizeOfRawData)


for entry in pe2.DIRECTORY_ENTRY_IMPORT:
    print('LLAMADAS A DLL')
    print('\t', entry.dll)
    print('\t\tLLAMADAS A FUNCIONES ')
    for function in entry.imports:
        print('\t\t\t', function.name)

print('TimeDateStamp: ' + pe2.FILE_HEADER.dump_dict()['TimeDateStamp']['Value'].split('[')[1][:-1])
print('TimeDateStamp: ' + hex(pe2.FILE_HEADER.TimeDateStamp))

#HASH SHA256 segun la pagina
#ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa