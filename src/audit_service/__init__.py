# Copyright (C) 2026 James Hickman
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

"""audit_service — the single deployment-wide audit writer.

Drains the aggregating security-event sink (a Redis Stream) that the core and
the other emitters publish to, demultiplexes each entry by tenant, and appends
it to that tenant's append-only ``audit_log`` (or ``public.audit_log_global``)
in the core Postgres — creating daily partitions on demand and acking only after
the DB commit. It is the sole writer of those tables (usage_logging_and_auditing
§5). A later phase adds the per-tenant hash chain (§7) and the security rules
engine (§11) to this same process.
"""

__version__ = "0.1.0"
