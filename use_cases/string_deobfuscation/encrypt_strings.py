'''
This script encrypts the strings in the executable _strdeobfus
created by the makefile, from source _strdeobfus.c. Creates new
executable strdeobfus, with encrypted strings in the data section and
which decrypts strings while executing.

Note: This is all just set-up to create a fake tiny piece of malware
`strdeobufs` which decrypts its strings upon execution.

'''

import lief
import os
import struct

# read in the original elf
raw_bin = lief.parse("_strdeobfus")

if raw_bin is None:
    raise Exception("Failed parsing binary file")
if not isinstance(raw_bin, lief.ELF.Binary):
    raise Exception("Binary is not an ELF")

bin: lief.ELF.Binary = raw_bin

data = bin.get_section(".data")

# find strings in data section that start/end with '$', which is the
# key it uses to decrypt.
strings = []
content = bytes(data.content)
k = ord('$')
i = 0
while i < len(content):
    if content[i] >= 32 and content[i] <= 126:
        start = i
        end = i
        while end < len(content) and (chr(content[end])).isprintable():
            end += 1                    
        s = content[start:end]
        # s is a string (all printable characters)
        if content[start] == k and content[end-1] == k:
            # collect positional info about strings in data section
            # that start & end with '$'
            posn = (start, end-1)
            strings.append(posn)
        i = end+1
    else:
        i += 1


c = data.content.tolist()
for (start, end) in strings:
    # replace each string that starts/ends with a '$' with content
    # between '$' that is xor-ed with '$'
    strdata = content[start:end+1]
    estrdata = [x^k for x in strdata[1:-1]]
    c = c[:start] + [k] + (list(estrdata)) + [k] + c[end+1:]

# NOTE: lief's section.content is a memoryview object,
# but it also accepts List[int].  No way to fix, just ignore.
data.content = (c) # type: ignore

# write out new version of the binary that decrypts strings in order
# to print them out meaning the strings don't exist in the program
# unencrypted.
bin.write("strdeobfus")
os.system("/usr/bin/chmod +x strdeobfus")

print("wrote strdeobfus, which has encrypted strings in its data section")
