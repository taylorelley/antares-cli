"""Interactive UI selection requires usable input and output terminals."""

from __future__ import annotations

from io import StringIO

from antares_cli.commands._interaction import can_interact


class _Stream(StringIO):
    def __init__(self, *, terminal: bool) -> None:
        super().__init__()
        self._terminal = terminal

    def isatty(self) -> bool:
        return self._terminal


def test_interaction_requires_both_terminal_streams() -> None:
    terminal = _Stream(terminal=True)
    redirected = _Stream(terminal=False)

    assert can_interact(stdin=terminal, stdout=terminal)
    assert not can_interact(stdin=redirected, stdout=terminal)
    assert not can_interact(stdin=terminal, stdout=redirected)
