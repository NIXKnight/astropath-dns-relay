# SPDX-License-Identifier: GPL-3.0-or-later
#
# astropath-dns-relay — self-hosted ACME DNS-01 solver gateway.
# Copyright (C) 2026  Saad Ali
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

"""Provider ABC + registry tests (T-M1-17, SPEC §5.1, §5.2)."""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from typing import Any

import pytest
from pydantic import BaseModel

from astropath.providers import base
from astropath.providers.base import (
    Provider,
    UnknownProvider,
    get_provider,
    register,
)


class _StubProvider(Provider):
    """Concrete-enough Provider whose only variable part is the ``type`` key.

    ``config_schema`` is defined here (annotation-only ``type`` in scope), so
    subclasses that assign ``type = "..."`` never re-reference the shadowed
    builtin in an annotation.
    """

    @classmethod
    def config_schema(cls) -> type[BaseModel]:
        return BaseModel

    @classmethod
    def from_config(cls, config: Mapping[str, Any], *, http: Any) -> Provider:
        return cls()

    async def present(self, zone: str, record_name: str, values: list[str]) -> None:
        return None

    async def cleanup(self, zone: str, record_name: str, values: list[str]) -> None:
        return None

    async def validate(self) -> None:
        return None


@pytest.fixture
def clean_registry() -> Iterator[None]:
    """Snapshot and restore ``REGISTRY`` so test providers do not leak."""
    saved = dict(base.REGISTRY)
    try:
        yield
    finally:
        base.REGISTRY.clear()
        base.REGISTRY.update(saved)


def test_register_and_resolve_by_type(clean_registry: None) -> None:
    @register
    class FakeProvider(_StubProvider):
        type = "fake-test"

    assert get_provider("fake-test") is FakeProvider


def test_unknown_type_rejected() -> None:
    with pytest.raises(UnknownProvider):
        get_provider("does-not-exist")


def test_duplicate_registration_rejected(clean_registry: None) -> None:
    @register
    class One(_StubProvider):
        type = "dup-test"

    with pytest.raises(ValueError, match="already registered"):

        @register
        class Two(_StubProvider):
            type = "dup-test"
