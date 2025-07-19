#!/usr/bin/env python3
"""
deobfuscator_pro.py – The Ultimate File Analysis & Deobfuscation Toolkit

This premium tool provides a comprehensive suite for analyzing and decoding
complex data formats. It integrates file identification, entropy analysis,
string extraction, hash identification, and a massive library of decoders.

This version is cleaned and optimized for compatibility with Pydroid3.
"""

# --- ✅ FIX FOR PYDROID3 OpenSSL ERROR ---
import os
os.environ['CRYPTOGRAPHY_OPENSSL_NO_LEGACY'] = '1'
# -----------------------------------------

import sys
import argparse
import base64
import binascii
import codecs
import urllib.parse
import html
import gzip
import zlib
import bz2
import lzma
import io
import tarfile
import zipfile
import re
from pathlib import Path
from typing import Tuple, Callable, Optional

# --- Optional Imports: Handled Gracefully for Pydroid3 ---
try:
    from rich.console import Console
    from rich.table import Table
    from rich.progress import Progress, BarColumn, TextColumn
    from rich.panel import Panel
    from rich.syntax import Syntax
    RICH_AVAILABLE = True
except ModuleNotFoundError:
    RICH_AVAILABLE = False
    class Console:
        def print(self, *args, **kwargs): print(*args)
    class Table:
        def __init__(self, **kwargs): pass
        def add_column(self, *args, **kwargs): pass
        def add_row(self, *args, **kwargs): pass
    Panel = Syntax = Progress = BarColumn = TextColumn = object

try:
    import brotli
except ModuleNotFoundError:
    brotli = None
try:
    from Crypto.Cipher import AES, DES, Blowfish, ChaCha20, ARC4
    from cryptography.fernet import Fernet
    CRYPTO_AVAILABLE = True
except ModuleNotFoundError:
    AES = DES = Blowfish = ChaCha20 = ARC4 = Fernet = None
    CRYPTO_AVAILABLE = False
try:
    from androguard.core.bytecodes.axml import AXMLPrinter
except ModuleNotFoundError:
    AXMLPrinter = None
try:
    import magic
except ModuleNotFoundError:
    magic = None
try:
    import jwt as pyjwt
except ModuleNotFoundError:
    pyjwt = None
try:
    from pyhashcat import Hashcat
except ModuleNotFoundError:
    Hashcat = None

# --- Constants & Utilities ---
ENGLISH_FREQ = {
    'a': 8.167, 'b': 1.492, 'c': 2.782, 'd': 4.253, 'e': 12.702, 'f': 2.228,
    'g': 2.015, 'h': 6.094, 'i': 6.966, 'j': 0.153, 'k': 0.772, 'l': 4.025,
    'm': 2.406, 'n': 6.749, 'o': 7.507, 'p': 1.929, 'q': 0.095, 'r': 5.987,
    's': 6.327, 't': 9.056, 'u': 2.758, 'v': 0.978, 'w': 2.360, 'x': 0.150,
    'y': 1.974, 'z': 0.074
}

class DeobfuscatorPro:
    def __init__(self):
        self.console = Console(highlight=False)
        self.key: Optional[bytes] = None
        self.iv: Optional[bytes] = None

        self.CODECS: dict[str, Callable[[bytes], Optional[bytes]]] = {
            "base64": self.dec_base64, "base32": self.dec_base32, "hex": self.dec_hex,
            "base58": self.dec_base58, "base85": self.dec_base85, "b85": self.dec_base85,
            "url": self.dec_url, "html": self.dec_html, "gzip": self.dec_gzip,
            "zlib": self.dec_zlib, "bz2": self.dec_bz2, "lzma": self.dec_lzma,
            "brotli": self.dec_brotli, "zip": self.dec_zip, "tar": self.dec_tar,
            "axml": self.dec_axml, "jwt": self.dec_jwt, "morse": self.dec_morse,
            "brainfuck": self.dec_brainfuck,
        }
        self.AUTO_ORDER = [
            "axml", "jwt", "base64", "base32", "hex", "base58", "base85", "url",
            "gzip", "zlib", "bz2", "lzma", "brotli", "zip", "tar", "rot13", "xor"
        ]

    def _looks_like_utf8(self, text: bytes) -> bool:
        try:
            text.decode("utf-8")
            return True
        except UnicodeDecodeError:
            return False

    def _looks_like_xml(self, text: bytes) -> bool:
        return b"<?xml" in text[:200] or text.lstrip().startswith(b"<")

    def _score_text_likelihood(self, text: bytes) -> float:
        text_lower = text.lower()
        score = 0
        printable_count = 0
        for byte in text_lower:
            if 32 <= byte <= 126:
                printable_count += 1
                char = chr(byte)
                if char in ENGLISH_FREQ:
                    score += ENGLISH_FREQ[char]

        printable_ratio = printable_count / len(text) if text else 0
        if printable_ratio < 0.85:
            return 0.0

        return score * printable_ratio

    def dec_base64(self, data: bytes) -> Optional[bytes]:
        try: return base64.b64decode(data, validate=True)
        except Exception: return None

    def dec_base32(self, data: bytes) -> Optional[bytes]:
        try: return base64.b32decode(data, casefold=True)
        except Exception: return None

    def dec_base58(self, data: bytes) -> Optional[bytes]:
        try: return base64.b58decode(data)
        except Exception: return None

    def dec_base85(self, data: bytes) -> Optional[bytes]:
        try: return base64.a85decode(data)
        except Exception: return None

    def dec_hex(self, data: bytes) -> Optional[bytes]:
        try: return binascii.unhexlify(data.strip())
        except Exception: return None

    def dec_url(self, data: bytes) -> Optional[bytes]:
        try: return urllib.parse.unquote_to_bytes(data.decode("ascii", "ignore"))
        except Exception: return None

    def dec_html(self, data: bytes) -> Optional[bytes]:
        try: return html.unescape(data.decode()).encode()
        except Exception: return None

    def dec_rot(self, data: bytes, n: int = 13) -> Optional[bytes]:
        try: return codecs.decode(data.decode("latin1"), f"rot_{n}").encode("latin1")
        except Exception: return None

    def dec_xor(self, data: bytes) -> Optional[bytes]:
        best_result: Optional[bytes] = None
        best_score = -1.0

        if self.key:
            key_byte = self.key[0]
            return bytes(b ^ key_byte for b in data)

        with Progress(TextColumn("[bold cyan]XOR Brute-force[/]"), BarColumn(), TextColumn("{task.completed}/{task.total} keys"), console=self.console, disable=not RICH_AVAILABLE) as progress:
            task = progress.add_task("Testing keys...", total=256)
            for k in range(256):
                out = bytes(b ^ k for b in data)
                score = self._score_text_likelihood(out)
                if score > best_score:
                    best_score = score
                    best_result = out
                progress.update(task, advance=1)

        return best_result if best_score > 0 else None

    def dec_gzip(self, data: bytes) -> Optional[bytes]:
        try: return gzip.decompress(data)
        except Exception: return None

    def dec_zlib(self, data: bytes) -> Optional[bytes]:
        try: return zlib.decompress(data)
        except Exception: return None

    def dec_bz2(self, data: bytes) -> Optional[bytes]:
        try: return bz2.decompress(data)
        except Exception: return None

    def dec_lzma(self, data: bytes) -> Optional[bytes]:
        try: return lzma.decompress(data)
        except Exception: return None

    def dec_brotli(self, data: bytes) -> Optional[bytes]:
        if brotli is None: return None
        try: return brotli.decompress(data)
        except Exception: return None

    def dec_zip(self, data: bytes) -> Optional[bytes]:
        try:
            with io.BytesIO(data) as bio, zipfile.ZipFile(bio) as zf:
                return zf.read(zf.namelist()[0])
        except Exception: return None

    def dec_tar(self, data: bytes) -> Optional[bytes]:
        try:
            with io.BytesIO(data) as bio, tarfile.open(fileobj=bio) as tf:
                member = tf.getmembers()[0]
                if member and member.isfile():
                    return tf.extractfile(member).read()
                return None
        except Exception: return None

    def dec_axml(self, data: bytes) -> Optional[bytes]:
        if AXMLPrinter is None or data[:4] != b"\x03\x00\x08\x00": return None
        try: return AXMLPrinter(data).get_xml().encode()
        except Exception: return None

    def dec_jwt(self, data: bytes) -> Optional[bytes]:
        if pyjwt is None: return None
        try:
            header = pyjwt.get_unverified_header(data)
            payload = pyjwt.decode(data, options={"verify_signature": False})
            return f"Header: {header}\nPayload: {payload}".encode()
        except Exception:
            return None

    def dec_morse(self, data: bytes) -> Optional[bytes]:
        MORSE_CODE_DICT = {
            '.-': 'A', '-...': 'B', '-.-.': 'C', '-..': 'D', '.': 'E', '..-.': 'F',
            '--.': 'G', '....': 'H', '..': 'I', '.---': 'J', '-.-': 'K', '.-..': 'L',
            '--': 'M', '-.': 'N', '---': 'O', '.--.': 'P', '--.-': 'Q', '.-.': 'R',
            '...': 'S', '-': 'T', '..-': 'U', '...-': 'V', '.--': 'W', '-..-': 'X',
            '-.--': 'Y', '--..': 'Z', '-----': '0', '.----': '1', '..---': '2',
            '...--': '3', '....-': '4', '.....': '5', '-....': '6', '--...': '7',
            '---..': '8', '----.': '9', '/': ' '
        }
        try:
            message = data.decode().strip()
            words = message.split(' / ')
            decoded_words = ["".join(MORSE_CODE_DICT[char] for char in word.split(' ') if char in MORSE_CODE_DICT) for word in words]
            return " ".join(decoded_words).encode()
        except Exception:
            return None

    def dec_brainfuck(self, data: bytes) -> Optional[bytes]:
        try:
            code = ''.join(filter(lambda x: x in '.[]<>-+', data.decode()))
            if not code: return None
            tape, ptr, output = [0] * 30000, 0, io.StringIO()
            i, limit, open_braces = 0, len(code), 0
            while i < limit:
                char = code[i]
                if char == '>': ptr += 1
                elif char == '<': ptr -= 1
                elif char == '+': tape[ptr] = (tape[ptr] + 1) % 256
                elif char == '-': tape[ptr] = (tape[ptr] - 1) % 256
                elif char == '.': output.write(chr(tape[ptr]))
                elif char == '[' and tape[ptr] == 0:
                    open_braces = 1
                    while open_braces > 0:
                        i += 1
                        if code[i] == '[': open_braces += 1
                        if code[i] == ']': open_braces -= 1
                elif char == ']' and tape[ptr] != 0:
                    open_braces = 1
                    while open_braces > 0:
                        i -= 1
                        if code[i] == ']': open_braces += 1
                        if code[i] == '[': open_braces -= 1
                i += 1
            return output.getvalue().encode()
        except Exception:
            return None

    def dec_symmetric(self, data: bytes, algo: str) -> Optional[bytes]:
        if not CRYPTO_AVAILABLE:
            self.console.print(f"[bold red][!] PyCryptodome(x) or cryptography is not installed. Cannot use '{algo}'.[/]")
            return None
        if not self.key:
            self.console.print(f"[bold red][!] --key is required for symmetric cipher '{algo}'.[/]")
            return None

        try:
            algo = algo.lower()
            if algo == "aes": cipher = AES.new(self.key, AES.MODE_CBC, self.iv or b"\x00" * 16)
            elif algo == "des": cipher = DES.new(self.key, DES.MODE_CBC, self.iv or b"\x00" * 8)
            elif algo == "blowfish": cipher = Blowfish.new(self.key, Blowfish.MODE_CBC, self.iv or b"\x00" * 8)
            elif algo == "chacha20": cipher = ChaCha20.new(key=self.key, nonce=self.iv)
            elif algo == "rc4": cipher = ARC4.new(self.key)
            elif algo == "fernet": return Fernet(self.key).decrypt(data)
            else: return None

            decrypted = cipher.decrypt(data)
            if algo in ["aes", "des", "blowfish"]:
                pad = decrypted[-1]
                if decrypted[-pad:] == bytes([pad]) * pad: return decrypted[:-pad]
            return decrypted
        except (ValueError, KeyError) as e:
            self.console.print(f"[bold red][!] Decryption failed for '{algo}': {e}[/]")
            return None

    def decode_once(self, codec: str, data: bytes) -> Optional[bytes]:
        codec_lc = codec.lower()
        if codec_lc.startswith("rot"):
            n = int(codec_lc[3:] or "13")
            return self.dec_rot(data, n)
        if codec_lc == "xor":
            return self.dec_xor(data)
        if codec_lc in {"aes", "des", "blowfish", "chacha20", "rc4", "fernet"}:
            return self.dec_symmetric(data, codec_lc)

        func = self.CODECS.get(codec_lc)
        return func(data) if func else None

    def auto_decode(self, data: bytes) -> Optional[Tuple[str, bytes]]:
        if magic:
            try:
                file_type = magic.from_buffer(data).lower()
                if 'gzip compressed data' in file_type:
                    if out := self.dec_gzip(data): return "gzip", out
                if 'zlib compressed data' in file_type:
                    if out := self.dec_zlib(data): return "zlib", out
                if 'zip archive' in file_type:
                    if out := self.dec_zip(data): return "zip", out
            except Exception:
                pass # Ignore magic errors on some platforms

        self.console.print("[cyan]Running auto-detection heuristics...[/]")
        for c in self.AUTO_ORDER:
            out = self.decode_once(c, data)
            if out and (self._looks_like_utf8(out) or self._looks_like_xml(out)):
                return c, out
        return None

    def decode_cli(self, args: argparse.Namespace):
        inp, outp = Path(args.input), Path(args.output)
        if not inp.exists():
            self.console.print(f"[bold red][!] Input file not found: {inp}[/]")
            sys.exit(1)

        raw = inp.read_bytes()
        self.key = (bytes.fromhex(args.key[2:]) if args.key and args.key.startswith("0x") else (args.key or '').encode()) if args.key else None
        self.iv = (bytes.fromhex(args.iv[2:]) if args.iv and args.iv.startswith("0x") else (args.iv or '').encode()) if args.iv else None

        data: Optional[bytes] = None
        codec_used = "N/A"

        if args.chain:
            chain = [c.strip() for c in args.chain.split(",") if c.strip()]
            data = raw
            for c in chain:
                decoded_step = self.decode_once(c, data)
                if decoded_step is None:
                    self.console.print(f"[bold red][!] Chain failed at step '{c}'.[/]")
                    sys.exit(1)
                data = decoded_step
            codec_used = "→".join(chain)
        elif args.force:
            data = self.decode_once(args.force, raw)
            codec_used = args.force
        elif args.auto:
            result = self.auto_decode(raw)
            if result:
                codec_used, data = result
        else:
            self.console.print("[bold yellow][!] No decoding mode selected. Use --auto, --force, or --chain.[/]")
            return

        if data is None:
            self.console.print(f"[bold red][!] Decoding failed for method '{codec_used}'.[/]")
            sys.exit(1)

        if self._looks_like_xml(data):
            try:
                import xml.dom.minidom as md
                data = md.parseString(data).toprettyxml(encoding="utf-8")
                self.console.print("[green]ⓘ Beautified XML output.[/]")
            except Exception:
                pass

        outp.write_bytes(data)
        self.console.print(f"\n[bold green][✓] Success![/bold green] Decoded via [bold cyan]{codec_used}[/bold cyan] and saved to [bold magenta]{outp}[/bold magenta]")

    def analyze_cli(self, args: argparse.Namespace):
        target = Path(args.file)
        if not target.exists():
            self.console.print(f"[bold red][!] File not found: {target}[/]")
            sys.exit(1)

        data = target.read_bytes()
        self.console.print(Panel(f"[bold cyan]Analysis Report for:[/] [magenta]{target}[/]", title="Deobfuscator Pro", border_style="blue"))

        file_type = "python-magic library not installed"
        if magic:
            try:
                file_type = magic.from_buffer(data)
            except Exception as e:
                file_type = f"magic failed: {e}"

        entropy = self._calculate_entropy(data)
        entropy_color = "green" if entropy < 6.0 else ("yellow" if entropy < 7.5 else "red")
        entropy_desc = "Low (likely text)" if entropy < 6.0 else ("Medium (compressed)" if entropy < 7.5 else "High (encrypted)")

        table = Table(title="File Properties")
        table.add_column("Metric", style="cyan", no_wrap=True)
        table.add_column("Value", style="white")
        table.add_column("Interpretation", style="yellow")
        table.add_row("File Size", f"{len(data):,} bytes", "")
        table.add_row("File Type", file_type, "Identified via libmagic")
        table.add_row(f"Shannon Entropy", f"[{entropy_color}]{entropy:.4f}[/{entropy_color}]", f"[{entropy_color}]{entropy_desc}[/{entropy_color}]")
        self.console.print(table)

        self._extract_strings(data)

    def _calculate_entropy(self, data: bytes) -> float:
        import math
        if not data: return 0.0
        counts = {byte: data.count(byte) for byte in set(data)}
        return -sum((count / len(data)) * math.log2(count / len(data)) for count in counts.values())

    def _extract_strings(self, data: bytes):
        self.console.print("\n[bold cyan]--- Found Strings (min. 6 chars) ---[/]")
        ascii_strings = re.findall(b"([ -~]{6,})", data)
        if ascii_strings:
            self.console.print(Syntax("\n".join(s.decode(errors='ignore') for s in ascii_strings), "strings", theme="monokai", line_numbers=False))

        # Corrected regex with 'r' for raw string to prevent SyntaxWarning
        urls = re.findall(rb'(https?://[A-Za-z0-9_./?=&-]+)', data)
        ips = re.findall(rb'([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})', data)

        if urls or ips:
            table = Table(title="Potential Network Indicators")
            table.add_column("Type", style="cyan")
            table.add_column("Indicator", style="yellow")
            for url in urls: table.add_row("URL", url.decode())
            for ip in ips: table.add_row("IP Address", ip.decode())
            self.console.print(table)

    def hash_id_cli(self, args: argparse.Namespace):
        if not Hashcat:
            self.console.print("[bold red][!] pyhashcat library not installed. Cannot identify hashes.[/]")
            sys.exit(1)

        results = Hashcat().identify(args.hash)
        if not results:
            self.console.print(f"[bold yellow][!] No matching hash types found for '{args.hash}'.[/]")
            return

        table = Table(title=f"Potential Hash Matches for '{args.hash}'")
        table.add_column("Hashcat Mode", style="cyan", justify="right")
        table.add_column("Hash Name", style="white")
        table.add_column("Category", style="yellow")
        for r in sorted(results, key=lambda x: x.mode):
            table.add_row(str(r.mode), r.name, r.category)
        self.console.print(table)

    def run(self):
        parser = argparse.ArgumentParser(description="Deobfuscator Pro - The Ultimate Toolkit.", formatter_class=argparse.RawTextHelpFormatter)
        subparsers = parser.add_subparsers(dest='command', required=True, help="Available commands")

        p_decode = subparsers.add_parser('decode', help='Decode a file using various algorithms.')
        p_decode.add_argument('-i', '--input', required=True, help='Input file to decode.')
        p_decode.add_argument('-o', '--output', required=True, help='Output file to save result.')
        p_decode.add_argument('--key', help='Hex (0x...) or raw string key for ciphers/xor.')
        # --- ✅ Typo Fix: p_deocde -> p_decode ---
        p_decode.add_argument('--iv', help='Hex (0x...) or raw string IV for ciphers.')
        group = p_decode.add_mutually_exclusive_group(required=True)
        group.add_argument('-f', '--force', help='Force a single codec (e.g., base64, aes).')
        group.add_argument('-c', '--chain', help='Comma-separated codec chain (e.g., base64,zlib).')
        group.add_argument('-a', '--auto', action='store_true', help='Use intelligent auto-detection.')
        p_decode.set_defaults(func=self.decode_cli)

        p_analyze = subparsers.add_parser('analyze', help='Perform a full analysis of a file.')
        p_analyze.add_argument('file', help='File to analyze.')
        p_analyze.set_defaults(func=self.analyze_cli)

        p_hash = subparsers.add_parser('hash-id', help='Identify the type of a given hash.')
        p_hash.add_argument('hash', help='The hash string to identify.')
        p_hash.set_defaults(func=self.hash_id_cli)

        if len(sys.argv) == 1:
            parser.print_help(sys.stderr)
            sys.exit(1)

        args = parser.parse_args()
        args.func(args)

if __name__ == "__main__":
    if not RICH_AVAILABLE:
        print("[Warning] 'rich' library not found. Falling back to basic text output.")
        print("          For the best experience, please install it: pip install rich")
    tool = DeobfuscatorPro()
    tool.run()

