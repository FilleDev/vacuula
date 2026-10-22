from __future__ import annotations
import re

from vacuula_server.constants import MINIMUM_INSTALLER_VERSION

# TODO: right now we support only X.X.X[-bX], in the future we might want to support more complex
# idea: for anything else versions have to match exactly? but whatever we do, update both version
# parsing in both FE, BE and build script!

_VERSION_RE = re.compile(r"^(\d+)\.(\d+)\.(\d+)(?:-b(\d+))?$")

def parse_version(v: str) -> tuple:
    m = _VERSION_RE.match(v.strip())
    if not m:
        return (-999, -999, -999, float("-inf"))
    major, minor, patch, beta = m.groups()
    # real version comes before beta
    beta_rank = int(beta) if beta is not None else float("inf")
    return (int(major), int(minor), int(patch), beta_rank)


def is_robot_outdated(installed_with: str) -> bool:
    if 'dev' in installed_with:
        return False # If you are messing with dev versions, I expect you to know what you are doing!
    return parse_version(installed_with) < parse_version(MINIMUM_INSTALLER_VERSION)