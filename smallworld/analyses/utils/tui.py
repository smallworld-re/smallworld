import logging


class TUIContinueException(Exception):
    """
    Exception for signaling that a TUI handler shouldn't exit the loop.
    """

    pass


class SimpleTUI:
    log = logging.getLogger("smallworld.tui")

    def __init__(self, help_banner="Available commands:"):
        self._cases = dict()
        self._shorts = dict()
        self._hints = dict()
        self._help_banner = help_banner
        self.add_case("help", self.print_help, hint="Print this message")

    def add_case(self, name, handler, hint=None):
        name = name.lower()
        short = name[0]
        if short in self._shorts:
            raise ValueError(
                "Colliding short name {short}: already bound for {self._shorts[short]}"
            )
        if name in self._cases:
            raise ValueError("Case {name} already registered")
        self._cases[name] = handler
        self._shorts[short] = name
        self._hints[name] = hint

    def print_help(self, **kwargs):
        self.log.warn(self._help_banner)
        for name in self._cases:
            self.log.warn(
                f'- {name} | {name[0]}:\t\t\t{self._hints[name] if self._hints[name] is not None else ""}'
            )
        raise TUIContinueException()

    def handle(self, _default, _disabled, **kwargs):
        prompt = " | ".join(
            map(
                lambda x: x.upper() if x == _default else x,
                filter(lambda x: x not in _disabled, self._cases.keys()),
            )
        )
        prompt = f"( {prompt} ) > "
        while True:
            opt = input(prompt).lower()
            if opt == "":
                if _default is None:
                    self.log.error("No default case available")
                    continue
                opt = _default

            if opt in self._shorts:
                opt = self._shorts[opt]

            if opt in _disabled:
                self.log.error("Option {opt} not available")
                continue

            if opt not in self._cases:
                self.log.error("Unknown option {opt}")
                continue

            try:
                return self._cases[opt](**kwargs)
            except TUIContinueException:
                continue
