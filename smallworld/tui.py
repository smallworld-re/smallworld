import curses
import logging

import angr

from .analyses.angr.guards import GuardTrackingScratchMixin
from .emulators import AngrEmulator
from .emulators.angr.scratch import ExpandedScratchPlugin

log = logging.getLogger(__name__)


class TUIScratchPlugin(GuardTrackingScratchMixin, ExpandedScratchPlugin):
    pass


class TUIExitException(Exception):
    pass


class TUI:
    def __init__(self, state):
        self.emu = AngrEmulator(
            arch=state.arch,
            mode=state.mode,
            byteorder=state.byteorder,
            preinit=self.preinit,
        )
        self.emu.enable_linear()
        state.apply(self.emu)

        self.n_steps = 0

        self.stdscr = None

        self.header = None
        self.header_field = None

        self.regs = None
        self.regs_names = None
        self.regs_data = None

        self.grds = None
        self.grds_names = None
        self.grds_data = None

        self.mem = None
        self.mem_nams = None
        self.mem_data = None

        self.input_box = None
        self.input_field = None

        self.scroll_regs = True
        self.scroll_mem = False
        self.scroll_grds = False

        self.regs_off = 0
        self.mem_off = 0
        self.grds_off = 0

        self.goto = None
        self.finish = None

    def preinit(self, emu):
        preset = angr.SimState._presets["default"].copy()
        preset.add_default_plugin("scratch", TUIScratchPlugin)
        emu._plugin_preset = preset

    def screen_init(self):
        self.header = self.stdscr.subwin(3, curses.COLS, 0, 0)
        self.header_field = self.header.subwin(1, curses.COLS - 2, 1, 1)

        regs_height = (curses.LINES - 6) // 2
        self.regs = self.stdscr.subwin(regs_height, curses.COLS // 2, 3, 0)
        self.regs_names = self.regs.derwin(regs_height - 2, 16, 1, 1)
        self.regs_data = self.regs.derwin(regs_height - 2, curses.COLS // 2 - 19, 1, 18)

        grds_height = (curses.LINES - 6) // 2 + ((curses.LINES - 6) % 2)
        self.grds = self.stdscr.subwin(
            grds_height, curses.COLS // 2, regs_height + 3, 0
        )
        self.grds_names = self.grds.derwin(grds_height - 2, 16, 1, 1)
        self.grds_data = self.grds.derwin(grds_height - 2, curses.COLS // 2 - 19, 1, 18)

        self.mem = self.stdscr.subwin(
            curses.LINES - 6, curses.COLS // 2, 3, curses.COLS // 2
        )
        self.mem_names = self.mem.derwin(curses.LINES - 8, 18, 1, 1)
        self.mem_data = self.mem.derwin(curses.LINES - 8, curses.COLS // 2 - 21, 1, 20)

        self.input_box = self.stdscr.subwin(3, curses.COLS, curses.LINES - 3, 0)
        self.input_field = self.input_box.derwin(1, curses.COLS - 2, 1, 1)

    def redraw_header(self):
        insn = self.emu.state.block().disassembly.insns[0]
        self.header_field.clear()
        self.header_field.addstr(0, 0, f"{insn}")
        self.header_field.noutrefresh()

    def redraw_regs(self):
        reg_vals = self.emu.state.registers.create_hint()

        self.regs_names.clear()
        self.regs_data.clear()
        self.regs_names.move(0, 0)
        self.regs_data.move(0, 0)
        names = list(
            filter(
                lambda x: not x.startswith("cc")
                and not x.endswith("_ns")
                and not x.endswith("_s"),
                reg_vals.keys(),
            )
        )
        names.sort()
        for name in names[self.regs_off :]:
            val = reg_vals[name]
            self.regs_names.addstr(name)
            try:
                self.regs_data.addstr(str(val))
                (y, x) = self.regs_data.getyx()
                self.regs_names.move(y + 1, 0)
                self.regs_data.move(y + 1, 0)
            except:
                break

        self.regs_names.noutrefresh()
        self.regs_data.noutrefresh()

    def redraw_mem(self):
        mem_vals = self.emu.state.memory.create_hint()

        self.mem_names.clear()
        self.mem_data.clear()
        self.mem_names.move(0, 0)
        self.mem_data.move(0, 0)
        names = list(mem_vals.keys())
        names.sort()
        for name in names[self.mem_off :]:
            val = mem_vals[name]
            self.mem_names.addstr(hex(name))
            for bound in self.emu.state.scratch.bounds:
                if name in bound:
                    val = "<Code>"
                    break
            try:
                self.mem_data.addstr(str(val))
                (y, x) = self.mem_data.getyx()
                self.mem_names.move(y + 1, 0)
                self.mem_data.move(y + 1, 0)
            except:
                break

        self.mem_names.noutrefresh()
        self.mem_data.noutrefresh()

    def redraw_guards(self):
        grds_vals = list(
            filter(lambda x: x[1].op != "BoolV", self.emu.state.scratch.guards[:-1])
        )
        grds_vals.reverse()

        self.grds_names.clear()
        self.grds_data.clear()
        self.grds_names.move(0, 0)
        self.grds_data.move(0, 0)

        for name, val in grds_vals[self.grds_off :]:
            self.grds_names.addstr(hex(name))
            try:
                self.grds_data.addstr(str(val))
                (y, x) = self.grds_data.getyx()
                self.grds_names.move(y + 1, 0)
                self.grds_data.move(y + 1, 0)
            except:
                break
        self.grds_names.noutrefresh()
        self.grds_data.noutrefresh()

    def redraw_borders(self):
        self.header.border()
        self.header.addstr(0, 1, "Instruction")
        if self.scroll_regs:
            self.regs.attron(curses.A_BOLD)
        else:
            self.regs.attroff(curses.A_BOLD)
        self.regs.border()
        self.regs.addstr(0, 1, "Registers")
        self.regs.noutrefresh()

        if self.scroll_mem:
            self.mem.attron(curses.A_BOLD)
        else:
            self.mem.attroff(curses.A_BOLD)
        self.mem.border()
        self.mem.addstr(0, 1, "Memory")
        self.mem.noutrefresh()

        if self.scroll_grds:
            self.grds.attron(curses.A_BOLD)
        else:
            self.grds.attroff(curses.A_BOLD)
        self.grds.border()
        self.grds.addstr(0, 1, "Guards")
        self.grds.noutrefresh()

        self.input_box.border()
        self.input_box.noutrefresh()

    def input_on(self, title):
        self.input_box.attron(curses.A_BOLD)
        self.input_box.border()
        self.input_box.addstr(0, 1, title)
        self.input_box.refresh()
        curses.echo()

    def input_off(self):
        self.input_box.attroff(curses.A_BOLD)
        self.input_box.border()
        self.input_box.refresh()
        curses.noecho()

    def handle_goto(self):
        if self.goto is not None and self.emu.state._ip.concrete_value == self.goto:
            self.goto = None

    def handle_finish(self):
        if self.finish is not None:
            insn = self.emu.state.block().disassembly.insns[0]
            is_return = False
            is_call = False

            # TODO: This is only implemented for arm32
            if insn.mnemonic == "pop" and "pc" in insn.op_str:
                # arm32-ism; you can pop a value into PC.
                # For the love of pudding I hope no one uses this to call.
                is_return = True
            elif insn.mnemonic == "bx" and "lr" in insn.op_str:
                # arm32 standard return; branch to lr
                is_return = True
            elif insn.mnemonic == "bl":
                # arm32 branch-and-link
                is_call = True

            if is_return:
                if self.finish == 0:
                    self.finish = None
                else:
                    self.finish -= 1
            elif is_call:
                self.finish += 1

    def cmd_goto(self):
        self.input_on("Goto")
        while True:
            try:
                goto = self.input_field.getstr(0, 0)
                if len(goto) == 0 or goto == b"q":
                    self.goto = None
                    break
                self.goto = int(goto, 16)
                break
            except:
                pass
            finally:
                self.input_field.clear()
                self.input_field.move(0, 0)
                self.input_field.refresh()
        self.input_off()
        return self.goto is not None

    def cmd_finish(self):
        self.finish = 0
        return True

    def cmd_quit(self):
        self.input_on("Quit (y/N)")
        while True:
            cmd = self.input_field.getstr(0, 0)
            if len(cmd) == 0 or cmd == b"n":
                self.input_field.clear()
                break
            elif cmd == b"y":
                raise TUIExitException()
        self.input_off()
        return False

    def cmd_left(self):
        if self.scroll_mem:
            self.scroll_mem = False
            self.scroll_regs = True
            self.redraw_borders()
            curses.doupdate()
        elif self.scroll_regs:
            self.scroll_regs = False
            self.scroll_grds = True
            self.redraw_borders()
            curses.doupdate()
        return False

    def cmd_right(self):
        if self.scroll_regs:
            self.scroll_regs = False
            self.scroll_mem = True
            self.redraw_borders()
            curses.doupdate()
            log.info("Mem active")
        elif self.scroll_grds:
            self.scroll_grds = False
            self.scroll_regs = True
            self.redraw_borders()
            curses.doupdate()
            log.info("Regs active")
        return False

    def cmd_up(self):
        if self.scroll_regs and self.regs_off > 0:
            self.regs_off -= 1
            self.redraw_regs()
        elif self.scroll_mem and self.mem_off > 0:
            self.mem_off -= 1
            self.redraw_mem()
        elif self.scroll_grds and self.grds_off > 0:
            self.grds_off -= 1
            self.redraw_grds()
        curses.doupdate()
        return False

    def cmd_down(self):
        # TODO: Stop scrolling at the bottom
        # This is difficult to figure,
        # since one entry can take more than one line
        if self.scroll_regs:
            self.regs_off += 1
            self.redraw_regs()
        elif self.scroll_mem:
            self.mem_off += 1
            self.redraw_mem()
        elif self.scroll_grds:
            self.grds_off += 1
            self.redraw_grds()
        curses.doupdate()
        return False

    def handle_input(self):
        cmd = self.stdscr.getch()
        if cmd == ord("g"):
            return self.cmd_goto()
        elif cmd == ord("f"):
            return self.cmd_finish()
        elif cmd == ord("q"):
            return self.cmd_quit()
        elif cmd == curses.KEY_LEFT:
            return self.cmd_left()
        elif cmd == curses.KEY_RIGHT:
            return self.cmd_right()
        elif cmd == curses.KEY_UP:
            return self.cmd_up()
        elif cmd == curses.KEY_DOWN:
            return self.cmd_down()
        return True

    def run(self, stdscr):
        self.stdscr = stdscr
        self.screen_init()

        self.redraw_borders()

        while True:
            self.n_steps += 1
            self.handle_goto()
            self.handle_finish()
            if self.goto is None and self.finish is None:
                self.regs_off = 0
                self.mem_off = 0
                self.grds_off = 0
                self.redraw_header()
                self.redraw_regs()
                self.redraw_mem()
                self.redraw_guards()
                curses.doupdate()

                try:
                    while not self.handle_input():
                        pass
                except TUIExitException:
                    break
            if self.emu.step(single_insn=True):
                break
        log.info(f"You finished {self.n_steps} instructions!")

    def start(self):
        curses.wrapper(self.run)
