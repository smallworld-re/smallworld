import struct

import lief

# this file is output by running strobfus (no args) it consists of
# 4-byte int (length) followed by string of that length these are the
# *encrypted* strings you want to stick back into data section of
# strdeobufs
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


raw_bin = lief.parse("strdeobfus")
if raw_bin is None:
    raise Exception("Failed parsing binary file")
if not isinstance(raw_bin, lief.ELF.Binary):
    raise Exception("Binary is not an ELF")
bin: lief.ELF.Binary = raw_bin

data = bin.get_section(".data")

c = data.content.tolist()

# this is gross.  We wrote strdeobfus.c s.t. strings start and end
# with $ and do not contain a $ internally.  Here we are ... kinda
# assuming that those will be the only $ in the data section which
# turns out to be true. This is how we figure out byte stretches
# in data section that need to be replaced


# assume that the only $ chars are start / end of strings
def find_dollars(s):
    dollar = ord("$")
    dollars = []
    for i in range(0, len(s)):
        if s[i] == dollar:
            dollars.append(i)
    return dollars


(s1, e1, s2, e2) = find_dollars(c)

# replace data section strings with encrypted versions
c = (
    c[:s1]
    + [x for x in enc_string1]
    + c[e1 + 1 : s2]
    + [x for x in enc_string2]
    + c[e2 + 1 :]
)
print(find_dollars(c))

# NOTE: lief's section.content is a memoryview object,
# but it also accepts List[int].  No way to fix, just ignore.
data.content = c    # type: ignore

# write out new version of the binary that decrypts strings in order to print them out
# meaning the strings don't exist in the original string
bin.write("strdeobfus2")
