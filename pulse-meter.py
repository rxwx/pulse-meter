#!/usr/bin/env python3
import re
import io
import os
import sys
import hashlib
import struct
import argparse
import yara
import zipfile

from Crypto.Cipher import DES3
from pathlib import Path
import logging

if sys.version_info.major != 3:
    logger.error("[!] Python3 required")
    sys.exit(1)

YARA_RULE_DIR = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'yara')

class CustomFormatter(logging.Formatter):

    grey = "\x1b[38;20m"
    yellow = "\x1b[33;20m"
    red = "\x1b[31;20m"
    bold_red = "\x1b[31;1m"
    reset = "\x1b[0m"
    format = "%(asctime)s - %(levelname)s - %(message)s"

    FORMATS = {
        logging.DEBUG: grey + format + reset,
        logging.INFO: grey + format + reset,
        logging.WARNING: yellow + format + reset,
        logging.ERROR: red + format + reset,
        logging.CRITICAL: bold_red + format + reset
    }

    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno)
        formatter = logging.Formatter(log_fmt)
        return formatter.format(record)

# create logger
logger = logging.getLogger("pulse_meter")
logger.setLevel(logging.DEBUG)

# create console handler with a higher log level
ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)
ch.setFormatter(CustomFormatter())
logger.addHandler(ch)

def decrypt(ciphertext, key, iv):
    k = DES3.adjust_key_parity(key)
    cipher = DES3.new(k, DES3.MODE_CFB, iv, segment_size=64)
    decrypted = cipher.decrypt(ciphertext)
    return decrypted

def encrypt(plaintext, key, iv):
    k = DES3.adjust_key_parity(key)
    cipher = DES3.new(k, DES3.MODE_CFB, iv, segment_size=64)
    encrypted = cipher.encrypt(plaintext)
    return encrypted

def parse_encrypted_config(filename, static_key):
    key = iv = ciphertext = ''
    f = open(filename, 'rb')
    f.seek(1)
    iv = f.read(8)
    key = static_key
    f.seek(1, 1) # 00 byte here, means hardcoded key
    size = struct.unpack('<i', f.read(4))[0]
    ciphertext = f.read(size)
    f.close()
    return key, iv, ciphertext

def match_callback(match):
  logger.critical(f"[Yara IOC] Rule: {match['rule']} ({match['meta']['description']}), Reference: {match['meta']['reference']}")
  return yara.CALLBACK_CONTINUE

def is_valid_snapshot(snapshot):
    # Validate snapshot
    if not snapshot.startswith(b'System state snapshot'):
        logger.error("Invalid snapshot file. Remember to decrypt the file first.")
        return False

    # Print the first line of the snapshot which contains the timestamp
    logger.info(snapshot[:snapshot.find(b'\n')].decode('utf-8'))
    return True

def parse_snapshot(snapshot):
    if not is_valid_snapshot(snapshot):
        return

    # Scan with Yara
    sources = {}
    for f in Path(YARA_RULE_DIR).glob('*.yar'):
        sources[os.path.basename(str(f).split('.')[0])] = str(f)
    rules = yara.compile(filepaths=sources)
    matches = rules.match(data=snapshot, callback=match_callback, which_callbacks=yara.CALLBACK_MATCHES)

    # Python parsing
    # TODO:
    # - get pulse hash and look up correct timestamp for files
    # - parse netstat output for IOCS / malicious connections

def parse_process_list(snapshot):
    if not is_valid_snapshot(snapshot):
        return

    processes = []
    snapshot_str = snapshot.decode('utf-8', errors='ignore')

    # Find the process list section
    ps_start = snapshot_str.find('Output of ps command')
    if ps_start == -1:
        logger.error("Could not find process list in snapshot")
        return processes

    # Find the end of the process
    lsof_start = snapshot_str.find('Output of lsof', ps_start)
    if lsof_start == -1:
        logger.error("Could not find end of process list in snapshot")
        return processes

    # Extract process list section
    process_section = snapshot_str[ps_start:lsof_start]
    lines = process_section.split('\n')

    # Skip the header lines
    header_found = False
    for i, line in enumerate(lines):
        if 'PID  PPID %CPU %MEM S  SIZE    VSZ   RSS COMMAND' in line.lstrip():
            header_found = True
            header_line = i
            break

    if not header_found:
        logger.error("Could not find process list header")
        return processes

    # Parse each process line
    for line in lines[header_line + 1:]:
        line = line.strip()
        if not line or line.startswith('Output of'):
            break

        # Split the line into columns
        parts = line.split()
        if len(parts) < 8:
            continue

        process = {
            'pid': parts[0],
            'ppid': parts[1],
            'cpu': parts[2],
            'mem': parts[3],
            'status': parts[4],
            'size': parts[5],
            'vsz': parts[6],
            'rss': parts[7],
            'command': ' '.join(parts[8:])
        }
        processes.append(process)

        # Log suspicious processes
        # TODO: log suspicious processes

    logger.info(f"Found {len(processes)} processes:")
    for process in processes:
        logger.info(f"{process['pid']}: {process['command']}")

    # List unique executables
    unique_executables = sorted(set(process['command'].split()[0] for process in processes))
    return processes, unique_executables


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Pulse Secure System Snapshot IOC Checker')
    parser.add_argument("action", help="Action", choices=('parse', 'decrypt', 'process_list'))
    parser.add_argument("input", help="Input file")
    parser.add_argument("--key", help="Key to use for decryption", required=False)
    args = parser.parse_args()

    if not os.path.exists(args.input):
        logger.error(f'Input file not found: {args.input}')
        sys.exit(1)

    if args.action == "parse":
        logger.info(f'Parsing snapshot file: {args.input}')

        with open(args.input, 'rb') as f:
            decrypted = f.read()

        parse_snapshot(decrypted)

    elif args.action == "process_list":
        logger.info(f'Parsing process list from snapshot file: {args.input}')
        with open(args.input, 'rb') as f:
            decrypted = f.read()

        parse_process_list(decrypted)

    elif args.action == "decrypt":
        if not args.key or not re.match(r'^[0-9a-fA-F]{48}$', args.key):
            logger.error("Invalid or missing --key flag")
            sys.exit(1)

        key = bytes.fromhex(args.key)

        key, iv, ciphertext = parse_encrypted_config(args.input, key)

        decrypted = decrypt(ciphertext, key, iv)
        logger.debug('Decrypted Snapshot')

        decrypted_buffer = io.BytesIO(decrypted)

        if not zipfile.is_zipfile(decrypted_buffer):
            logger.error("File was not decrypted correctly. Ensure the key is correct.")
            sys.exit(1)

        # Extract the snapshot file from the zip
        with zipfile.ZipFile(decrypted_buffer) as zf:
            for file in zf.namelist():
                decrypted_file = os.path.basename(file)
                with open(decrypted_file, 'wb') as f:
                    f.write(zf.read(file))
                    logger.info(f'Wrote decrypted file: {decrypted_file}')

