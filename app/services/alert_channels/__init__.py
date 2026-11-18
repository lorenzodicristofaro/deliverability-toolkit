"""The alert channels by kind (M7-15 contract in `app.services.alert_dispatch`).

`CHANNELS` is read by `default_registry()`. M7-17..19 add their lines here.
"""

from __future__ import annotations

from typing import Final

from app.services.alert_channels.email import EmailChannel
from app.services.alert_dispatch import Channel

CHANNELS: Final[dict[str, Channel]] = {"email": EmailChannel()}

__all__ = ["CHANNELS"]
