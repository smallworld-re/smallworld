''' 

This script encrypts the strings in the executable _strdeobfus created
by the makefile, from source _strdeobfus.c. 

'''

import lief
import os
import struct

# The file `new_strings` is created by running _strdeobfus with no
# args. Contents are 4-byte uint (length) followed by string of that
# length.  These are the *encrypted* strings you'll want to stick back
# into data section of _strdeobufs to create the version that has
# encrypted strings that are decrypted by running the program.

# read encrypted strings
with open("new_strings", "rb") as s:

    def read_str(s):
        nb = s.read(4)
        n = struct.unpack("<i", nb)[0]
        # print(f"{n} bytes string")
        st = s.read(n)
        # print (f"str {st}")
        return st

    enc_string1 = read_str(s)
    enc_string2 = read_str(s)

print(f"found enc_string1 = [{enc_string1}]")
print(f"found enc_string2 = [{enc_string2}]")

# read in the original elf
raw_bin = lief.parse("_strdeobfus")
if raw_bin is None:
    raise Exception("Failed parsing binary file")
if not isinstance(raw_bin, lief.ELF.Binary):
    raise Exception("Binary is not an ELF")
bin: lief.ELF.Binary = raw_bin

data = bin.get_section(".data")

c = data.content.tolist()

# this is gross.  We wrote _strdeobfus.c s.t. strings start and end
# with $ and do not contain a $ internally.  Here we are ... kinda
# assuming that those will be the only $ in the data section which
# turns out to be true. This is how we figure out byte stretches
# in data section that need to be replaced.
# None of this is resilient but it does work for this example.

# assume that the only $ chars are start / end of strings
def find_dollars(s):
    dollar = ord("$")
    dollars = []
    for i in range(0, len(s)):
        if s[i] == dollar:
            dollars.append(i)
    return dollars

(s1, e1, s2, e2) = find_dollars(c)
print(f"Found $-delimited strings in data section: {s1,e1,s2,e2}")

# replace data section strings with encrypted versions
c = (
    c[:s1]
    + [x for x in enc_string1]
    + c[e1 + 1 : s2]
    + [x for x in enc_string2]
    + c[e2 + 1 :]
)

# NOTE: lief's section.content is a memoryview object,
# but it also accepts List[int].  No way to fix, just ignore.
data.content = c  # type: ignore

# write out new version of the binary that decrypts strings in order
# to print them out meaning the strings don't exist in the program
# unencrypted.
bin.write("strdeobfus")
os.system("/usr/bin/chmod +x strdeobfus")

print("wrote strdeobfus, which has encrypted strings in its data section")
