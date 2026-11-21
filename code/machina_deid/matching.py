"""Boundary-aware literal matching for corpus-wide identity and filename maps."""

from __future__ import annotations

from collections.abc import Iterable, Mapping

import ahocorasick


def _word_char(char: str, underscore: bool) -> bool:
    return (char.isascii() and char.isalnum()) or (underscore and char == "_")


class TokenMatcher:
    def __init__(self, replacements: Mapping[str, str], *, filenames: bool = False):
        self.filenames = filenames
        self.automaton = ahocorasick.Automaton()
        for token, replacement in replacements.items():
            self.automaton.add_word(token.lower(), (token.lower(), replacement))
        if self.automaton:
            self.automaton.make_automaton()

    def matches(self, text: str, lowered: str):
        if not self.automaton:
            return
        for end, (token, replacement) in self.automaton.iter(lowered):
            start = end + 1 - len(token)
            end += 1
            if (self.filenames or token[0].isalnum()) and start and _word_char(text[start - 1], self.filenames):
                continue
            if (self.filenames or token[-1].isalnum()) and end < len(text) and _word_char(text[end], self.filenames):
                continue
            yield start, end, replacement


def replace_tokens(text: str, matchers: Iterable[TokenMatcher]) -> str:
    lowered = text.lower()
    if len(lowered) != len(text):
        # A capital dotted I expands when lowercased. Keep source offsets usable.
        lowered = text.replace("\u0130", "i").lower()
    matches = [match for matcher in matchers for match in matcher.matches(text, lowered)]
    if not matches:
        return text
    matches.sort(key=lambda match: (match[0], -match[1]))
    pieces = []
    cursor = 0
    for start, end, replacement in matches:
        if start >= cursor:
            pieces.extend((text[cursor:start], replacement))
            cursor = end
    pieces.append(text[cursor:])
    return "".join(pieces)
