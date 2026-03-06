"""Base class for rule-based analyzers."""

from __future__ import annotations

from abc import ABC, abstractmethod

from codeguardian.models import DiffFile, Finding


class Rule(ABC):
    """Base rule that inspects diff files for issues."""

    @property
    @abstractmethod
    def name(self) -> str: ...

    @abstractmethod
    def check(self, file: DiffFile) -> list[Finding]:
        """Run this rule against a diff file and return findings."""
        ...

    def _matches_extensions(self, path: str, extensions: set[str]) -> bool:
        return any(path.endswith(ext) for ext in extensions)
