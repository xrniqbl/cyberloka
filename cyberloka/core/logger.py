"""Rich-powered logger."""
from __future__ import annotations

import logging

from rich.console import Console
from rich.logging import RichHandler

_console = Console()


def get_console() -> Console:
    return _console


def get_logger(name: str = "cyberloka", level: int = logging.INFO) -> logging.Logger:
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger
    logger.setLevel(level)
    handler = RichHandler(
        console=_console,
        show_time=True,
        show_path=False,
        markup=True,
        rich_tracebacks=True,
    )
    handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(handler)
    logger.propagate = False
    return logger
