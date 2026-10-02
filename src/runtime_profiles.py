"""Verified UnityFramework layouts; never reuse fixed addresses across builds.

Profiles are selected by LC_UUID, which survives the converter's link-edit
rewrites. Patch entry bytes and semantic anchors are checked separately.
The 4.0.1 profile is offline-verified; device validation is still required.
"""
from dataclasses import dataclass
from uuid import UUID


@dataclass(frozen=True)
class RuntimeProfile:
    version: str
    quit_sites: tuple[int, int]
    crash_callback: int
    availability_entry: int
    cfstring: int
    bundle_literal: int
    bundle_stub: int
    bundle_selref: int
    asio_cave: int
    bundle_cave: int
    availability_cave: int


PROFILES = {
    "eb37107f-8e9c-3f5d-85b8-c2d9dc84c853": RuntimeProfile(
        "4.0.0", (0x38E8964, 0x38E89B4), 0x89A668, 0x143B914,
        0x47A1C20, 0x4360FC4, 0x3BF46C0, 0x47CBDB8,
        0x444CE00, 0x444CEC0, 0x444CF30),
    "6e181f31-750a-3044-a73a-1498dc2d56d4": RuntimeProfile(
        "4.0.1", (0x391D28C, 0x391D2DC), 0x8A1CD4, 0x144363C,
        0x47DEC68, 0x439C724, 0x3C2AF80, 0x4807DB8,
        0x44891A0, 0x44891A0, 0x44891A0),
}


def profile_for(m):
    commands = m.lc(0x1B)
    if len(commands) != 1 or len(commands[0]["raw"]) != 24:
        raise SystemExit("UnityFramework must contain exactly one valid LC_UUID")
    identity = str(UUID(bytes=bytes(commands[0]["raw"][8:24])))
    if identity not in PROFILES:
        raise SystemExit("Unsupported UnityFramework build (UUID %s); "
                         "refusing version-specific patches." % identity)
    return PROFILES[identity]


def require_bytes(m, va, expected, purpose):
    offset = m.foff(va)
    if offset is None or bytes(m.buf[offset:offset + len(expected)]) != expected:
        raise SystemExit("%s: unexpected bytes at 0x%X; refusing patch" % (purpose, va))
    return offset
