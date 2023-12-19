from smallworld import hinting, utils

hinter = hinting.getHinter(__name__)

utils.setup_hinting(verbose=True, stream=True, file="hints.jsonl")

try:
    hinter.warning("test")
except:
    pass
else:
    assert False

hinter.debug(hinting.Hint("set register: EAX"))
hinter.info(hinting.Hint("read memory at address: 0xdeadbeef"))
hinter.warning(hinting.Hint("unidentified register: XYZ"))
