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

"""DNS provider backends and the provider registry (SPEC §5).

Importing this package imports every built-in provider module so their
``@register`` decorators populate :data:`astropath.providers.base.REGISTRY`
(the startup fail-fast in T-M1-26 relies on the registry being populated).
"""

from astropath.providers.hurricane import HurricaneProvider
from astropath.providers.route53 import Route53Provider

__all__ = ["HurricaneProvider", "Route53Provider"]
