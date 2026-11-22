#!/usr/bin/env python3
"""Console for the AX8052 flasher on an ESP32-S3.

Uses the Windows serial API in the Python standard library. No packages.
DTR and RTS stay off so opening the port does not reset the ESP32-S3.

    python flash.py COM5 help
    python flash.py COM5 unlock
    python flash.py COM5 read 0 40
    python flash.py COM5 read 0 8000 --out firmware.bin
    python flash.py COM5 write 0 00000000
    python flash.py COM5 flash firmware.bin --addr 0x200 --steps 4
    python flash.py COM5 erase
    python flash.py COM5 setkey FFFFFFFFFFFFFFFF
    python flash.py COM5 pc
    python flash.py COM5 steps 4

Addresses and lengths on read, dump, and write are hex, as on the console.
steps takes a decimal count from 1 to 16.
"""

from __future__ import print_function

import argparse
import ctypes
import os
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
HEX_KEY = re.compile(r"^[0-9A-Fa-f]{16}$")
HEX_BYTES = re.compile(r"^[0-9A-Fa-f]*$")
CHUNK = 128
CALIB = 0xFC00
SCAN_LINES = 29

FAIL_EXACT = {
    "ack",
    "pc reply",
    "calibration page",
    "write range",
    "write needs an even address and an even length",
    "range exceeds code space",
    "code config ack",
    "short dump reply",
    "setkey range",
    "setkey reply",
    "erase reply",
    "erase incomplete",
    "status after erase",
    "steps 1..16",
    "key needs 16 hex digits",
    "setkey needs 16 hex digits",
    "read <addr> <len>",
    "write <addr> <hexbytes>",
    "unknown, help",
    "line too long",
    "capture setup failed",
    "poll none",
}


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


def parse_hex(text):
    value = text.strip().lower()
    if value.startswith("0x"):
        value = value[2:]
    if not value or any(c not in "0123456789abcdef" for c in value):
        raise ValueError("not hex: %s" % text)
    return int(value, 16)


def parse_number(text):
    return int(text, 0)


def parse_dump(text):
    out = bytearray()
    for line in text.splitlines():
        match = READ_LINE.match(line.strip())
        if not match:
            continue
        for part in match.group(2).split():
            out.append(int(part, 16))
    return out


def failure_line(text):
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("locked:") or stripped.startswith("link:") or stripped.startswith("stop:"):
            return stripped
        if stripped.startswith("read:"):
            return stripped
        if stripped in FAIL_EXACT:
            return stripped
    return None


def drain(port):
    time.sleep(0.15)
    quiet = time.monotonic()
    while time.monotonic() - quiet < 0.15:
        chunk = port.read_some()
        if chunk:
            quiet = time.monotonic()
        else:
            time.sleep(0.02)


def transact(port, cmd, seconds, done):
    print(">> " + cmd)
    port.write(cmd + "\n")
    deadline = time.monotonic() + seconds
    got = ""
    while time.monotonic() < deadline:
        chunk = port.read_some()
        if chunk:
            got += chunk.decode("ascii", "replace")
            if failure_line(got) or done(got):
                time.sleep(0.2)
                extra = port.read_some()
                if extra:
                    got += extra.decode("ascii", "replace")
                sys.stdout.write(got)
                if got and not got.endswith("\n"):
                    sys.stdout.write("\n")
                bad = failure_line(got)
                if bad:
                    raise RuntimeError(bad)
                return got
        time.sleep(0.04)
    if got:
        sys.stdout.write(got)
        if not got.endswith("\n"):
            sys.stdout.write("\n")
    raise TimeoutError("timeout waiting after %s" % cmd)


def expect(port, cmd, seconds, needle, count=1):
    def done(text):
        return text.count(needle) >= count
    return transact(port, cmd, seconds, done)


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


def check_key(text):
    if not HEX_KEY.match(text):
        raise ValueError("key needs 16 hex digits")
    return text.upper()


def check_write_chunk(addr, hex_bytes):
    if addr & 1:
        raise ValueError("address must be even")
    if not HEX_BYTES.match(hex_bytes) or (len(hex_bytes) & 1) or len(hex_bytes) == 0:
        raise ValueError("write needs an even number of hex digits")
    nbytes = len(hex_bytes) // 2
    if nbytes > CHUNK or (nbytes & 1):
        raise ValueError("write takes an even length, at most 128 bytes")
    if addr + nbytes > CALIB:
        raise ValueError("image reaches the calibration page")


def read_memory(port, addr, length, out_path):
    if length <= 0 or addr + length > 0x10000:
        raise ValueError("range exceeds code space")
    last = addr + ((length - 1) // 16) * 16
    needle = "%04X:" % last
    seconds = 15 + (length * 8) // 100
    reply = expect(port, "read %X %X" % (addr, length), seconds, needle)
    data = parse_dump(reply)
    if len(data) != length:
        raise ValueError("read back %d bytes, asked for %d" % (len(data), length))
    if out_path:
        with open(out_path, "wb") as fh:
            fh.write(data)
        print("saved %s (%d bytes)" % (out_path, len(data)))
    return data


def program(port, addr, data, steps):
    expect(port, "unlock", 20, "unlocked 1")
    off = 0
    while off < len(data):
        n = min(CHUNK, len(data) - off)
        hex_bytes = "".join("%02X" % b for b in data[off:off + n])
        expect(port, "write %04X %s" % (addr + off, hex_bytes), 30, "write ok")
        off += n
    got = bytearray()
    left = len(data)
    pos = addr
    while left:
        n = min(CHUNK, left)
        reply = expect(port, "read %04X %X" % (pos, n), 15 + (n * 8) // 100, "%04X:" % pos)
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
        expect(port, "steps %X" % steps, 40, "pc ", steps + 1)


def run_command(port, args):
    cmd = args.cmd
    if cmd == "help":
        expect(port, "help", 5, "Do not power the AX8052 from 5 V.")
    elif cmd == "pins":
        expect(port, "pins", 5, "DBG_EN")
    elif cmd == "key":
        expect(port, "key " + check_key(args.hexkey), 5, "key ok")
    elif cmd == "setkey":
        expect(port, "setkey " + check_key(args.hexkey), 30, "setkey ok")
    elif cmd in ("unlock", "status"):
        expect(port, cmd, 20, "unlocked ")
    elif cmd in ("read", "dump"):
        read_memory(port, parse_hex(args.addr), parse_hex(args.length), args.out)
    elif cmd == "write":
        addr = parse_hex(args.addr)
        check_write_chunk(addr, args.hex)
        expect(port, "write %04X %s" % (addr, args.hex.upper()), 30, "write ok")
    elif cmd == "flash":
        data = load_image(args.image, args.addr)
        program(port, args.addr, data, args.steps)
    elif cmd == "erase":
        expect(port, "erase", 90, "erase done")
    elif cmd == "pc":
        expect(port, "pc", 20, "pc ")
    elif cmd == "reset":
        expect(port, "reset", 20, "pc ")
    elif cmd == "step":
        expect(port, "step", 20, "pc ")
    elif cmd == "steps":
        if args.n < 1 or args.n > 16:
            raise ValueError("steps must be 1..16")
        expect(port, "steps %X" % args.n, 40, "pc ", args.n + 1)
    elif cmd == "loop":
        expect(port, "loop", 10, "loop high")
    elif cmd in ("bits", "bitsod"):
        expect(port, cmd, 15, "zeros ")
    elif cmd in ("wire5", "wire6"):
        expect(port, cmd, 20, "zeros ", 5)
    elif cmd == "trace":
        expect(port, "trace", 20, "trace listen lows")
    elif cmd == "sense":
        expect(port, "sense", 15, "sense CLK drive")
    elif cmd == "scan":
        def done(text):
            return len(re.findall(r"(?m)^scan \d+ ", text)) >= SCAN_LINES
        transact(port, "scan", 30, done)
    else:
        raise ValueError("unknown command %s" % cmd)


def build_parser():
    parser = argparse.ArgumentParser(
        description="Drive the AX8052 flasher console on an ESP32-S3.")
    parser.add_argument("port", help="serial port of the ESP32-S3")
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("help", help="print the console command list")
    sub.add_parser("pins", help="print the ESP32 GPIO numbers")

    key = sub.add_parser("key", help="keep the unlock key in the ESP32")
    key.add_argument("hexkey", help="16 hex digits, high byte first")
    setkey = sub.add_parser("setkey", help="program the debug key into the chip")
    setkey.add_argument("hexkey", help="16 hex digits, high byte first")

    sub.add_parser("unlock", help="open the port and print status")
    sub.add_parser("status", help="same as unlock")

    for name in ("read", "dump"):
        reader = sub.add_parser(name, help="read code flash")
        reader.add_argument("addr", help="hex start address")
        reader.add_argument("length", help="hex byte count")
        reader.add_argument("--out", help="also write the raw bytes to this file")

    writer = sub.add_parser("write", help="program one hex chunk, at most 128 bytes")
    writer.add_argument("addr", help="even hex address, below FC00")
    writer.add_argument("hex", help="even number of hex digits")

    image = sub.add_parser("flash", help="write a .bin, read it back, compare")
    image.add_argument("image", help="firmware file")
    image.add_argument("--addr", default="0", type=parse_number, help="start address, decimal or 0x hex")
    image.add_argument("--steps", default=0, type=int, help="after a match, step the core 1..16 times")

    sub.add_parser("erase", help="secure-erase the main flash and the debug key")
    sub.add_parser("pc", help="print the program counter")
    sub.add_parser("reset", help="reset the CPU, leave it halted, print the counter")
    sub.add_parser("step", help="execute one instruction and print the counter")
    steps = sub.add_parser("steps", help="reset, then step N times, in one session")
    steps.add_argument("n", type=int, help="decimal count 1..16")

    sub.add_parser("loop", help="check that DATA_IN follows DATA_OUT")
    sub.add_parser("bits", help="96 clocks with the buffer driving")
    sub.add_parser("bitsod", help="96 clocks with DATA_OUT released")
    sub.add_parser("wire5", help="sample the GPIO5 data wire")
    sub.add_parser("wire6", help="sample the GPIO6 data wire")
    sub.add_parser("trace", help="trace CLK, DBG_EN, RESET_N, and DATA")
    sub.add_parser("sense", help="read the four debug pins")
    sub.add_parser("scan", help="read the header pins")
    return parser


def main(argv):
    # python flash.py COM5 firmware.bin  is the flash command.
    if len(argv) >= 2 and not argv[1].startswith("-") and os.path.isfile(argv[1]):
        argv = [argv[0], "flash"] + argv[1:]
    parser = build_parser()
    args = parser.parse_args(argv)
    if getattr(args, "steps", 0) < 0 or getattr(args, "steps", 0) > 16:
        parser.error("steps must be 0..16")
    port = Port(args.port)
    try:
        drain(port)
        run_command(port, args)
    finally:
        port.close()


if __name__ == "__main__":
    try:
        main(sys.argv[1:])
    except (OSError, ValueError, TimeoutError, RuntimeError) as exc:
        print(exc, file=sys.stderr)
        sys.exit(1)
