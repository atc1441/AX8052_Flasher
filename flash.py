#!/usr/bin/env python3
"""Write a .bin into an AX8052 through the ESP32-S3 flasher console.

Uses the Windows console API in the Python standard library. No packages.
DTR and RTS stay off so opening the port does not reset the ESP32-S3.

    python flash.py COM24 firmware.bin
    python flash.py COM24 firmware.bin --addr 0x200
    python flash.py COM24 firmware.bin --steps 4
"""

from __future__ import print_function

import argparse
import ctypes
import re
import sys
import time
from ctypes import wintypes

GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
OPEN_EXISTING = 3
FILE_ATTRIBUTE_NORMAL = 0x80
CLRRTS = 4
CLRDTR = 6
PURGE_RXCLEAR = 0x0008
PURGE_TXCLEAR = 0x0004
NOPARITY = 0
ONESTOPBIT = 0
MAXDWORD = 0xFFFFFFFF

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)


class DCB(ctypes.Structure):
    _fields_ = [
        ("DCBlength", wintypes.DWORD),
        ("BaudRate", wintypes.DWORD),
        ("fBinary", wintypes.DWORD, 1),
        ("fParity", wintypes.DWORD, 1),
        ("fOutxCtsFlow", wintypes.DWORD, 1),
        ("fOutxDsrFlow", wintypes.DWORD, 1),
        ("fDtrControl", wintypes.DWORD, 2),
        ("fDsrSensitivity", wintypes.DWORD, 1),
        ("fTXContinueOnXoff", wintypes.DWORD, 1),
        ("fOutX", wintypes.DWORD, 1),
        ("fInX", wintypes.DWORD, 1),
        ("fErrorChar", wintypes.DWORD, 1),
        ("fNull", wintypes.DWORD, 1),
        ("fRtsControl", wintypes.DWORD, 2),
        ("fAbortOnError", wintypes.DWORD, 1),
        ("fDummy2", wintypes.DWORD, 17),
        ("wReserved", wintypes.WORD),
        ("XonLim", wintypes.WORD),
        ("XoffLim", wintypes.WORD),
        ("ByteSize", wintypes.BYTE),
        ("Parity", wintypes.BYTE),
        ("StopBits", wintypes.BYTE),
        ("XonChar", ctypes.c_char),
        ("XoffChar", ctypes.c_char),
        ("ErrorChar", ctypes.c_char),
        ("EofChar", ctypes.c_char),
        ("EvtChar", ctypes.c_char),
        ("wReserved1", wintypes.WORD),
    ]


class COMMTIMEOUTS(ctypes.Structure):
    _fields_ = [
        ("ReadIntervalTimeout", wintypes.DWORD),
        ("ReadTotalTimeoutMultiplier", wintypes.DWORD),
        ("ReadTotalTimeoutConstant", wintypes.DWORD),
        ("WriteTotalTimeoutMultiplier", wintypes.DWORD),
        ("WriteTotalTimeoutConstant", wintypes.DWORD),
    ]


kernel32.CreateFileW.argtypes = [
    wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID,
    wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE,
]
kernel32.CreateFileW.restype = wintypes.HANDLE
kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
kernel32.CloseHandle.restype = wintypes.BOOL
kernel32.EscapeCommFunction.argtypes = [wintypes.HANDLE, wintypes.DWORD]
kernel32.EscapeCommFunction.restype = wintypes.BOOL
kernel32.GetCommState.argtypes = [wintypes.HANDLE, ctypes.POINTER(DCB)]
kernel32.GetCommState.restype = wintypes.BOOL
kernel32.SetCommState.argtypes = [wintypes.HANDLE, ctypes.POINTER(DCB)]
kernel32.SetCommState.restype = wintypes.BOOL
kernel32.SetCommTimeouts.argtypes = [wintypes.HANDLE, ctypes.POINTER(COMMTIMEOUTS)]
kernel32.SetCommTimeouts.restype = wintypes.BOOL
kernel32.PurgeComm.argtypes = [wintypes.HANDLE, wintypes.DWORD]
kernel32.PurgeComm.restype = wintypes.BOOL
kernel32.ClearCommError.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD), wintypes.LPVOID]
kernel32.ClearCommError.restype = wintypes.BOOL
kernel32.WriteFile.argtypes = [
    wintypes.HANDLE, wintypes.LPCVOID, wintypes.DWORD,
    ctypes.POINTER(wintypes.DWORD), wintypes.LPVOID,
]
kernel32.WriteFile.restype = wintypes.BOOL
kernel32.ReadFile.argtypes = [
    wintypes.HANDLE, wintypes.LPVOID, wintypes.DWORD,
    ctypes.POINTER(wintypes.DWORD), wintypes.LPVOID,
]
kernel32.ReadFile.restype = wintypes.BOOL
kernel32.FlushFileBuffers.argtypes = [wintypes.HANDLE]
kernel32.FlushFileBuffers.restype = wintypes.BOOL

READ_LINE = re.compile(r"^([0-9A-Fa-f]{4}):((?:\s+[0-9A-Fa-f]{2})+)\s*$")
CHUNK = 128
CALIB = 0xFC00


class Port(object):
    def __init__(self, name):
        path = name if name.startswith("\\\\.\\") else "\\\\.\\" + name
        self.h = kernel32.CreateFileW(
            path, GENERIC_READ | GENERIC_WRITE, 0, None, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, None)
        if self.h is None or self.h == wintypes.HANDLE(-1).value:
            err = ctypes.get_last_error()
            raise OSError("cannot open %s (Windows error %d)" % (name, err))
        self._hands_off()
        self._configure()
        self._hands_off()
        kernel32.PurgeComm(self.h, PURGE_RXCLEAR | PURGE_TXCLEAR)

    def _hands_off(self):
        kernel32.EscapeCommFunction(self.h, CLRDTR)
        kernel32.EscapeCommFunction(self.h, CLRRTS)
        errors = wintypes.DWORD(0)
        kernel32.ClearCommError(self.h, ctypes.byref(errors), None)

    def _configure(self):
        dcb = DCB()
        dcb.DCBlength = ctypes.sizeof(DCB)
        if not kernel32.GetCommState(self.h, ctypes.byref(dcb)):
            raise OSError("GetCommState failed (%d)" % ctypes.get_last_error())
        dcb.BaudRate = 115200
        dcb.ByteSize = 8
        dcb.Parity = NOPARITY
        dcb.StopBits = ONESTOPBIT
        dcb.fBinary = 1
        dcb.fParity = 0
        dcb.fOutxCtsFlow = 0
        dcb.fOutxDsrFlow = 0
        dcb.fDtrControl = 0
        dcb.fDsrSensitivity = 0
        dcb.fTXContinueOnXoff = 0
        dcb.fOutX = 0
        dcb.fInX = 0
        dcb.fErrorChar = 0
        dcb.fNull = 0
        dcb.fRtsControl = 0
        dcb.fAbortOnError = 0
        if not kernel32.SetCommState(self.h, ctypes.byref(dcb)):
            raise OSError("SetCommState failed (%d)" % ctypes.get_last_error())
        timeouts = COMMTIMEOUTS(MAXDWORD, 0, 0, 0, 2000)
        if not kernel32.SetCommTimeouts(self.h, ctypes.byref(timeouts)):
            raise OSError("SetCommTimeouts failed (%d)" % ctypes.get_last_error())

    def close(self):
        if self.h:
            kernel32.CloseHandle(self.h)
            self.h = None

    def write(self, text):
        data = text.encode("ascii")
        done = wintypes.DWORD(0)
        if not kernel32.WriteFile(self.h, data, len(data), ctypes.byref(done), None):
            raise OSError("write failed (%d)" % ctypes.get_last_error())
        if done.value != len(data):
            raise OSError("short write")
        kernel32.FlushFileBuffers(self.h)

    def read_some(self):
        buf = ctypes.create_string_buffer(4096)
        done = wintypes.DWORD(0)
        if not kernel32.ReadFile(self.h, buf, 4096, ctypes.byref(done), None):
            raise OSError("read failed (%d)" % ctypes.get_last_error())
        if done.value == 0:
            return b""
        return buf.raw[:done.value]


def load_image(path, addr):
    with open(path, "rb") as fh:
        data = bytearray(fh.read())
    if not data:
        raise ValueError("empty image")
    if addr & 1:
        raise ValueError("address must be even")
    if len(data) & 1:
        data.append(0xFF)
    if addr + len(data) > CALIB:
        raise ValueError("image reaches the calibration page")
    return data


def parse_dump(text):
    out = bytearray()
    for line in text.splitlines():
        match = READ_LINE.match(line.strip())
        if not match:
            continue
        for part in match.group(2).split():
            out.append(int(part, 16))
    return out


def send(port, cmd, needle, seconds, count=1):
    print(">> " + cmd)
    port.write(cmd + "\n")
    deadline = time.monotonic() + seconds
    got = ""
    while time.monotonic() < deadline:
        chunk = port.read_some()
        if chunk:
            got += chunk.decode("ascii", "replace")
            if got.count(needle) >= count:
                time.sleep(0.2)
                extra = port.read_some()
                if extra:
                    got += extra.decode("ascii", "replace")
                sys.stdout.write(got)
                if not got.endswith("\n"):
                    sys.stdout.write("\n")
                return got
        time.sleep(0.04)
    sys.stdout.write(got)
    raise TimeoutError("timeout waiting for %r after %s" % (needle, cmd))


def program(port, addr, data, steps):
    time.sleep(0.3)
    while port.read_some():
        pass
    send(port, "unlock", "unlocked 1", 20)
    off = 0
    while off < len(data):
        n = min(CHUNK, len(data) - off)
        hex_bytes = "".join("%02X" % b for b in data[off:off + n])
        send(port, "write %04X %s" % (addr + off, hex_bytes), "write ok", 30)
        off += n
    got = bytearray()
    left = len(data)
    pos = addr
    while left:
        n = min(CHUNK, left)
        reply = send(port, "read %04X %X" % (pos, n), "%04X:" % pos, 30)
        got.extend(parse_dump(reply))
        pos += n
        left -= n
    if len(got) != len(data):
        raise ValueError("read back %d bytes, image has %d" % (len(got), len(data)))
    for i, (flash, image) in enumerate(zip(got, data)):
        if flash != image:
            raise ValueError("mismatch at %04X: flash %02X image %02X" % (addr + i, flash, image))
    print("image matches")
    if steps:
        send(port, "steps %X" % steps, "pc ", 40, steps + 1)


def parse_addr(text):
    return int(text, 0)


def main(argv):
    parser = argparse.ArgumentParser(description="Write a .bin to an AX8052 via the ESP32-S3 flasher.")
    parser.add_argument("port", help="serial port, for example COM24")
    parser.add_argument("image", help="firmware .bin")
    parser.add_argument("--addr", default="0", type=parse_addr, help="even start address (default 0)")
    parser.add_argument("--steps", default=0, type=int, help="after a match, reset and step this many times (0..16)")
    args = parser.parse_args(argv)
    if args.steps < 0 or args.steps > 16:
        parser.error("steps must be 0..16")
    data = load_image(args.image, args.addr)
    port = Port(args.port)
    try:
        program(port, args.addr, data, args.steps)
    finally:
        port.close()


if __name__ == "__main__":
    try:
        main(sys.argv[1:])
    except (OSError, ValueError, TimeoutError) as exc:
        print(exc, file=sys.stderr)
        sys.exit(1)
