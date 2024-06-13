import argparse

import pypcode

from smallworld.state import Register, RegisterAlias


def parse_args():
    parser = argparse.ArgumentParser("Derive a CPU definition from a Pcode language")
    parser.add_argument("-s", "--strict", action="store_true")
    parser.add_argument("-P", "--uc-const-pkg", default=None)
    parser.add_argument("-R", "--uc-reg-prefix", default=None)
    parser.add_argument("arch")
    parser.add_argument("mode")
    parser.add_argument("endian")
    parser.add_argument("language")
    return parser.parse_args()


args = parse_args()

ctx = pypcode.Context(args.language)

uc_reg_names = None
if args.uc_const_pkg is not None:
    uc_const_pkg = __import__(f"unicorn.{args.uc_const_pkg}", fromlist=["unicorn"])
    uc_reg_names = set(
        filter(lambda x: x.startswith(args.uc_reg_prefix), dir(uc_const_pkg))
    )

regs = list(map(lambda x: (x[1], x[0]), ctx.registers.items()))
regs.sort(key=lambda x: (x[0].offset << 32) + (2**32 - x[0].size))

model_regs = dict()

uc_reg_found = set()

curr = None
curr_model = None

for reg, name in regs:
    uc_reg = f"{args.uc_reg_prefix}{name.upper()}"
    if uc_reg_names is not None and uc_reg not in uc_reg_names:
        # This register is probably an artifact fof Sleigh.
        continue
    elif curr is None or reg.offset >= curr.offset + curr.size:
        # We've moved out of the region covered by the current register.
        # Our next register is the new base register.
        curr = reg
        curr_model = Register(name, width=reg.size)
        model_regs[name] = curr_model
        uc_reg_found.add(uc_reg)
    else:
        # This register is an alias into the current register.
        model_regs[name] = RegisterAlias(
            name, curr_model, width=reg.size, offset=reg.offset - curr.offset
        )
        uc_reg_found.add(uc_reg)

if args.strict and uc_reg_names is not None and len(uc_reg_names - uc_reg_found):
    for reg in uc_reg_names - uc_reg_found:
        print(f"Missing {reg}")
    raise ValueError("Missing registers from unicorn")

print("class NewCPUState(CPU):")
print(f'    """Auto-generated CPU state for {args.arch}:{args.mode}:{args.endian}')
print("")
print(f"    Generated from Pcode language {args.language},")
print(f"    and Unicorn package unicorn.{args.uc_const_pkg}")
print('    """')
print()
print(f'    arch="{args.arch}"')
print(f'    mode="{args.mode}"')
print(f'    endian="{args.endian}"')
print("")
print("    def __init__(self):")
for name, reg in model_regs.items():
    if isinstance(reg, RegisterAlias):
        rep = f'RegisterAlias("{reg.name}", self.{reg.reference.name}, width={reg.width}, offset={reg.offset})'
    else:
        rep = f'Register("{reg.name}", width={reg.width})'
    print(f"        self.{name} = {rep}")
