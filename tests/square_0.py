# NOTE: you have to get rid of hints file first before
# hinting gets set up. that is, right here.
import os
hintsfile = "hints.jsonl"
if os.path.exists(hintsfile):
    os.remove(hintsfile)

import logging
from smallworld import utils
import smallworld.smallworld as sw

utils.setup_logging(level=logging.INFO)

# create a small world
conf = sw.X86_64()
smw = sw.Smallworld(config=conf)

# NOTE: code is of type bytes
code = open("square.bin", "rb").read()

# map the code into memory at this address
smw.map_code(base=0x1000, entry=0x1000, code=code)

# analyze the code given that entry point
# output: this will log hints both to stdout and to the file "hints.jsonl"
smw.analyze()
