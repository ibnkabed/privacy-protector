"""Live microphone sessions from Windows (WASAPI), without administrator rights.

Every program that opens an audio input device creates an "audio session" on it, and the
session lasts as long as the process does: active while capturing, inactive after. So
reading the sessions gives the process ID of everyone who has opened the microphone during
its lifetime, and whether it is capturing now. Devices are not opened and no audio is read.

Limits: a use that starts and ends between two reads shows up as an inactive session
without its time; and what does not create a session (opening the device with low-level
methods) does not appear here, so it is supplemented by the Windows permission log.
"""

from __future__ import annotations

import ctypes
import os
from ctypes import POINTER, byref, c_int, c_long, c_uint, c_void_p, c_wchar_p
from typing import Any

IS_WINDOWS = os.name == "nt"

SESSION_INACTIVE, SESSION_ACTIVE, SESSION_EXPIRED = 0, 1, 2
E_CAPTURE = 1
DEVICE_STATE_ACTIVE = 0x1
CLSCTX_ALL = 0x17
COINIT_MULTITHREADED = 0x0
RPC_E_CHANGED_MODE = -2147417850


class GUID(ctypes.Structure):
    _fields_ = [("Data1", ctypes.c_uint32), ("Data2", ctypes.c_uint16), ("Data3", ctypes.c_uint16), ("Data4", ctypes.c_ubyte * 8)]

    @classmethod
    def parse(cls, text: str) -> "GUID":
        import uuid

        raw = uuid.UUID(text).bytes_le
        guid = cls()
        ctypes.memmove(byref(guid), raw, 16)
        return guid


CLSID_MMDeviceEnumerator = GUID.parse("BCDE0395-E52F-467C-8E3D-C4579291692E")
IID_IMMDeviceEnumerator = GUID.parse("A95664D2-9614-4F35-A746-DE8DB63617E6")
IID_IAudioSessionManager2 = GUID.parse("77AA99A0-1BD6-484F-8BC7-2C654C9A9B6F")
IID_IAudioSessionControl2 = GUID.parse("BFB7FF88-7239-4FC9-8FA2-07C950BE9C6D")


def _method(pointer: c_void_p, index: int, *argtypes: Any) -> Any:
    table = ctypes.cast(pointer, POINTER(POINTER(c_void_p)))[0]
    prototype = ctypes.WINFUNCTYPE(c_long, c_void_p, *argtypes)
    function = prototype(table[index])
    return lambda *args: function(pointer, *args)


def _release(pointer: c_void_p) -> None:
    if pointer and pointer.value:
        _method(pointer, 2)()


def _ok(result: int) -> bool:
    return int(result) >= 0


class _COM:
    """Initializes COM once per thread, and uninitializes it when the thread ends."""

    def __init__(self) -> None:
        self.ole32 = ctypes.windll.ole32
        result = self.ole32.CoInitializeEx(None, COINIT_MULTITHREADED)
        # If the thread was already initialized in another mode, work is still possible,
        # but uninitializing is not ours to do.
        self.owned = _ok(result)
        if not self.owned and result != RPC_E_CHANGED_MODE and result != 1:
            raise OSError(f"CoInitializeEx failed: {result:#x}")

    def close(self) -> None:
        if self.owned:
            self.ole32.CoUninitialize()
            self.owned = False


class AudioSessionReader:
    """A reader that stays alive in one thread, so COM is not reinitialized on every read.

    It is created, used and closed in the same thread.
    """

    def __init__(self) -> None:
        self.com: _COM | None = None
        self.enumerator = c_void_p()

    def _open(self) -> None:
        if self.enumerator.value:
            return
        self.com = self.com or _COM()
        if not _ok(self.com.ole32.CoCreateInstance(byref(CLSID_MMDeviceEnumerator), None, CLSCTX_ALL,
                                                   byref(IID_IMMDeviceEnumerator), byref(self.enumerator))):
            self.enumerator = c_void_p()
            raise OSError("MMDeviceEnumerator unavailable")

    def read(self) -> list[dict[str, Any]]:
        """Every audio session on the active input devices: process ID, state and device."""
        if not IS_WINDOWS:
            return []
        self._open()
        rows: list[dict[str, Any]] = []
        collection = c_void_p()
        try:
            if not _ok(_method(self.enumerator, 3, c_int, c_uint, POINTER(c_void_p))(E_CAPTURE, DEVICE_STATE_ACTIVE, byref(collection))):
                # The audio service may invalidate the enumerator after it restarts; it is
                # recreated on the next read.
                _release(self.enumerator)
                self.enumerator = c_void_p()
                raise OSError("EnumAudioEndpoints failed")
            count = c_uint()
            _method(collection, 3, POINTER(c_uint))(byref(count))
            for index in range(count.value):
                rows.extend(_device_sessions(collection, index))
        finally:
            _release(collection)
        return rows

    def close(self) -> None:
        _release(self.enumerator)
        self.enumerator = c_void_p()
        if self.com:
            self.com.close()
            self.com = None
def capture_sessions() -> list[dict[str, Any]]:
    reader = AudioSessionReader()
    try:
        return reader.read()
    finally:
        reader.close()


def _device_sessions(collection: c_void_p, index: int) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    device = c_void_p()
    manager = c_void_p()
    sessions = c_void_p()
    try:
        if not _ok(_method(collection, 4, c_uint, POINTER(c_void_p))(index, byref(device))):
            return rows
        raw_id = c_wchar_p()
        device_id = ""
        if _ok(_method(device, 5, POINTER(c_wchar_p))(byref(raw_id))) and raw_id.value:
            device_id = raw_id.value
            ctypes.windll.ole32.CoTaskMemFree(raw_id)
        if not _ok(_method(device, 3, POINTER(GUID), c_uint, c_void_p, POINTER(c_void_p))(
                byref(IID_IAudioSessionManager2), CLSCTX_ALL, None, byref(manager))):
            return rows
        if not _ok(_method(manager, 5, POINTER(c_void_p))(byref(sessions))):
            return rows
        total = c_int()
        _method(sessions, 3, POINTER(c_int))(byref(total))
        for position in range(total.value):
            control = c_void_p()
            control2 = c_void_p()
            try:
                if not _ok(_method(sessions, 4, c_int, POINTER(c_void_p))(position, byref(control))):
                    continue
                if not _ok(_method(control, 0, POINTER(GUID), POINTER(c_void_p))(byref(IID_IAudioSessionControl2), byref(control2))):
                    continue
                state = c_int()
                _method(control2, 3, POINTER(c_int))(byref(state))
                pid = c_uint()
                _method(control2, 14, POINTER(c_uint))(byref(pid))
                # 15 = IsSystemSoundsSession: returns S_OK (0) for the system sounds session.
                system_sounds = _method(control2, 15)() == 0
                if system_sounds or not pid.value:
                    continue
                rows.append({"pid": int(pid.value), "state": int(state.value), "device": device_id})
            finally:
                _release(control2)
                _release(control)
    finally:
        _release(sessions)
        _release(manager)
        _release(device)
    return rows


if __name__ == "__main__":  # manual check: python capability_audio.py
    for row in capture_sessions():
        print(row)
