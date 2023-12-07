from smallworld import hinting
from smallworld import utils

hinter = hinting.getHinter(__name__)

utils.setup_hinting(verbose=True, stream=True, file="hints.jsonl")

try:
    hinter.warning("test")
except:
    pass
else:
    assert False

info_hint = hinting.UnderSpecifiedRegisterHint(message="This is a info hint", register="rdi")
hinter.info(info_hint)