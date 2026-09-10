"""Authorized network scanning and packet analysis toolkit."""

import logging

from .version import __version__

# Without this, a warning raised while nothing has configured logging goes to
# logging.lastResort and prints on stderr - which is somebody else's output,
# and in a test run is noise nobody asked for. The application attaches its
# own handler; see netroach.frozen_backend.
logging.getLogger(__name__).addHandler(logging.NullHandler())

__all__ = ["__version__"]
