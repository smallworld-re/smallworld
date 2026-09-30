"""Parse Ghidra compiler specifications (``.cspec``) as pypcode ships them.

Stage 1 only (stdlib ElementTree; the SLEIGH register lookup needs pypcode).
The parse is structural and faithful; interpretation happens in stage 2.

Semantics notes (Ghidra 12.1, ``Ghidra/Features/Decompiler/src/decompile/
cpp/fspec.cc``):

* ``storage=`` and ``metatype=`` on ``<pentry>`` are synonyms
  (``ParamEntry::decode``): ``general``, ``float``, ``ptr``, ``hiddenret``,
  ``vector``, ``class1``-``class4``.
* A register in neither ``<unaffected>`` nor ``<killedbycall>`` has an
  unknown effect, so ``<killedbycall>`` is not a complete caller-saved list.
* Stack offsets are relative to the stack pointer at function entry, after
  the call has pushed any return address.
* ``<data_organization>`` overrides the ``DataOrganizationImpl`` defaults
  below.
"""

import typing
import xml.etree.ElementTree as ET

Json = typing.Dict[str, typing.Any]

# DataOrganizationImpl defaults (Ghidra 12.1; unchanged since 11.4).
DATA_ORG_DEFAULTS: Json = {
    "absolute_max_alignment": 0,
    "machine_alignment": 8,
    "default_alignment": 1,
    "default_pointer_alignment": 4,
    "pointer_size": None,
    "pointer_shift": 0,
    "char_size": 1,
    "char_signed": True,
    "wchar_size": 2,
    "short_size": 2,
    "integer_size": 4,
    "long_size": 4,
    "long_long_size": 8,
    "float_size": 4,
    "double_size": 8,
    "long_double_size": 8,
}


def _int(value: typing.Optional[str]) -> typing.Any:
    if value is None:
        return None
    try:
        return int(value, 0)
    except ValueError:
        return value  # e.g. extrapop="unknown"


def parse_varnode_ref(e: ET.Element) -> Json:
    """``<register name=/>``, ``<varnode space= offset= size=/>`` or
    ``<addr .../>`` (a ``join`` space names its pieces)."""
    if e.tag == "register":
        return {"kind": "register", "name": e.attrib["name"]}
    ref: Json = {"kind": e.tag}
    for key, value in e.attrib.items():
        ref[key] = _int(value) if key in ("offset", "size") else value
    space = e.attrib.get("space")
    if space == "join":
        ref["kind"] = "join"
        pieces = sorted(
            (k for k in e.attrib if k.startswith("piece")), key=lambda k: int(k[5:])
        )
        ref["pieces"] = [e.attrib[k] for k in pieces]
    elif space == "stack":
        ref["kind"] = "stack"
    return ref


def parse_pentry(e: ET.Element, group: typing.Optional[int]) -> Json:
    entry: Json = {}
    for key, value in e.attrib.items():
        entry[key] = (
            _int(value) if key in ("minsize", "maxsize", "align", "size") else value
        )
    entry["storage_class"] = (
        e.attrib.get("storage") or e.attrib.get("metatype") or "general"
    )
    children = list(e)
    if len(children) != 1:
        raise ValueError(f"pentry with {len(children)} locations: {ET.tostring(e)!r}")
    entry["loc"] = parse_varnode_ref(children[0])
    if group is not None:
        entry["group"] = group
    return entry


def parse_rule(e: ET.Element) -> Json:
    """A ``<rule>``: filters (``<datatype>``, ...) then actions."""
    filters: typing.List[Json] = []
    actions: typing.List[Json] = []
    filter_tags = {"datatype", "datatype_at", "varargs", "position", "and", "or"}
    for child in e:
        item: Json = {"tag": child.tag, **child.attrib}
        (filters if child.tag in filter_tags else actions).append(item)
    return {"filters": filters, "actions": actions}


def parse_paramlist(e: typing.Optional[ET.Element]) -> typing.Optional[Json]:
    if e is None:
        return None
    out: Json = {"attrs": dict(e.attrib), "entries": [], "rules": [], "other": []}
    group = 0
    for child in e:
        if child.tag == "pentry":
            out["entries"].append(parse_pentry(child, None))
        elif child.tag == "group":
            for pentry in child:
                out["entries"].append(parse_pentry(pentry, group))
            group += 1
        elif child.tag == "rule":
            out["rules"].append(parse_rule(child))
        else:
            out["other"].append(child.tag)
    return out


_EFFECT_LISTS = (
    "unaffected",
    "killedbycall",
    "likelytrash",
    "internal_storage",
    "returnaddress",
)


def parse_prototype(e: ET.Element, is_default: bool) -> Json:
    proto: Json = {
        "name": e.attrib.get("name"),
        "is_default": is_default,
        "extrapop": _int(e.attrib.get("extrapop")),
        "stackshift": _int(e.attrib.get("stackshift")),
        "strategy": e.attrib.get("strategy"),
        "input": parse_paramlist(e.find("input")),
        "output": parse_paramlist(e.find("output")),
    }
    for tag in _EFFECT_LISTS:
        child = e.find(tag)
        proto[tag] = None if child is None else [parse_varnode_ref(c) for c in child]
    known = {"input", "output", "localrange", "paramrange", "pcode", *_EFFECT_LISTS}
    proto["unparsed_children"] = sorted({c.tag for c in e if c.tag not in known})
    return proto


def parse_data_org(
    root: ET.Element, default_pointer_size: typing.Optional[int]
) -> Json:
    """The effective data organization: Ghidra's defaults plus the cspec's."""
    element = root.find("data_organization")
    explicit: Json = {}
    if element is not None:
        for child in element:
            if child.tag == "char_type":
                explicit["char_signed"] = (
                    child.attrib.get("signed", "true").lower() == "true"
                )
            elif child.tag in DATA_ORG_DEFAULTS:
                explicit[child.tag] = _int(child.attrib.get("value"))
    effective = dict(DATA_ORG_DEFAULTS)
    effective["pointer_size"] = default_pointer_size
    effective.update(explicit)
    return effective


def parse_cspec(path: str, default_pointer_size: typing.Optional[int]) -> Json:
    """The parts of a cspec the generator reads, and every prototype."""
    root = ET.parse(path).getroot()
    stackpointer = root.find("stackpointer")
    returnaddress = root.find("returnaddress")
    prototypes = []
    default_proto = root.find("default_proto")
    if default_proto is not None:
        prototypes += [
            parse_prototype(p, True) for p in default_proto.findall("prototype")
        ]
    prototypes += [parse_prototype(p, False) for p in root.findall("prototype")]
    return {
        "data_organization": parse_data_org(root, default_pointer_size),
        "stackpointer": None if stackpointer is None else dict(stackpointer.attrib),
        "returnaddress": (
            None
            if returnaddress is None
            else [parse_varnode_ref(c) for c in returnaddress]
        ),
        "prototypes": prototypes,
    }


def prototype_lines(text: str, name: str) -> typing.Tuple[int, int]:
    """The 1-based line range of prototype `name` in cspec source `text`."""
    lines = text.splitlines()
    start = None
    for number, line in enumerate(lines, 1):
        if start is None and f'<prototype name="{name}"' in line:
            start = number
        elif start is not None and "</prototype>" in line:
            return start, number
    raise ValueError(f"prototype {name!r} not found")


def register_names(value: typing.Any) -> typing.Set[str]:
    """Every register name a parsed structure mentions (join pieces too)."""
    names: typing.Set[str] = set()
    if isinstance(value, dict):
        if value.get("kind") == "register":
            names.add(value["name"])
        if value.get("kind") == "join":
            names.update(value["pieces"])
        for item in value.values():
            names |= register_names(item)
    elif isinstance(value, list):
        for item in value:
            names |= register_names(item)
    return names


def sleigh_registers(
    pypcode: typing.Any, language: str, names: typing.Iterable[str]
) -> Json:
    """name -> {space, offset, size, containing}: the SLEIGH register table
    entries for `names`, with the larger registers that contain each."""
    # Keep the Context alive while its varnodes are read: they point into it,
    # and reading them after it is collected crashes (pypcode 3.3.3).
    context = pypcode.Context(language)
    registers = context.registers
    everything = [(n, v.space.name, v.offset, v.size) for n, v in registers.items()]
    table: Json = {}
    for name in sorted(names):
        varnode = registers.get(name)
        if varnode is None:
            table[name] = {"missing": True}
            continue
        space, offset, size = varnode.space.name, varnode.offset, varnode.size
        containing = sorted(
            (s, n)
            for n, sp, o, s in everything
            if sp == space and o <= offset and offset + size <= o + s and s > size
        )
        table[name] = {
            "space": space,
            "offset": offset,
            "size": size,
            "containing": [n for _, n in containing],
        }
    del context
    return table
