from typing import Optional

import typer
from capstone import CS_ARCH_X86, CS_MODE_64, Cs
from rich.console import Console
from rich.layout import Layout
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table
from typing_extensions import Annotated

debug = ""


def callstack_panel():
    return Panel(
        "0x1234567890ABCDEF\n0xDEADBEEFDEADBEEF\n0x1111111111111111\n0x2222222222222222\n0x1111111111111111\n0x2222222222222222\n0x3333333333333333\n[bold]0x0000000000000000",
        title="Callstack",
    )


def display_value(value, width):
    if value is None:
        return "?" * (width + 2)
    return f"{value:#0{(width + 2)}x}"


def register_panel(env, step):
    register_table = Table()

    register_table.add_column("Register")
    register_table.add_column("Value")
    register_table.add_column("Info")

    step_info = env["step"][step]
    for r in env["registers"]:
        highlight = None
        if step_info["highlight_registers"] == r:
            highlight = "bold"
        register_table.add_row(
            r,
            display_value(step_info["registers"][r], 16),
            env["register_info"][r],
            style=highlight,
        )

    return register_table
    # return Panel(register_table, title="Registers")


def stack_panel(env, step):
    stack = ""
    step_info = env["step"][step]

    for i in range(20):
        stack += (
            "[bold]"
            + display_value(step_info["registers"]["rsp"] + (i * 16), 16)
            + ":[/bold] "
            + display_value(step_info["stack"][i], 16)
            + "\n"
        )

    return Panel(stack, title="Stack")


def code_panel(env, step):
    code_string = ""
    rip = env["step"][step]["registers"]["rip"]
    with open(env["code"], "rb") as code_file:
        code = code_file.read()
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        for i in md.disasm(code, 0x0):
            if i.address == rip:
                code_string += "[bold]"
            code_string += (
                "0x%x:\t%s\t%s" % (i.address, i.mnemonic, escape(i.op_str)) + "\n"
            )
            if i.address == rip:
                code_string += "[/bold]"
    return Panel(code_string, title="Code")


def hint_panel(env, step):
    step_info = env["step"][step]
    hint_string = ""
    for hint in step_info["hints"]:
        if hint["level"] == "warn":
            hint_string += "[italic]" + hint["message"] + "[/italic]\n"
        if hint["level"] == "alert":
            hint_string += "[bold]" + hint["message"] + "[/bold]\n"

    return Panel(hint_string, title="Hints")


def draw_hint(env, step):
    console = Console()
    layout = Layout()

    layout.split_column(
        Layout(name="context", size=21), Layout(name="code"), Layout(name="clues")
    )
    layout["context"].split_row(
        callstack_panel(), register_panel(env, step), stack_panel(env, step)
    )
    layout["code"].update(code_panel(env, step))
    layout["clues"].update(hint_panel(env, step))
    console.print(layout)


def main(
    environment: Annotated[typer.FileText, typer.Argument()],
    step: Annotated[Optional[int], typer.Option()] = 0,
):
    env = eval(environment.read())
    draw_hint(env, step)


if __name__ == "__main__":
    typer.run(main)
