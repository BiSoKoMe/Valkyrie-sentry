"""Registry constants for pure fixtures on hosts without the Windows module.

No registry operations are provided, so an accidental real read/write fails.
"""
try:
    import winreg as constants
except ImportError:
    from types import SimpleNamespace

    constants = SimpleNamespace(
        HKEY_LOCAL_MACHINE=0x80000002,
        HKEY_CURRENT_USER=0x80000001,
        HKEY_USERS=0x80000003,
        KEY_READ=0x20019,
        KEY_SET_VALUE=0x0002,
        REG_SZ=1,
        REG_DWORD=4,
    )
