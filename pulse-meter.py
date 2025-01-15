#!/usr/bin/env python3
import re
import io
import os
import sys
import hashlib
import struct
import argparse
import yara
import json
import zipfile
import logging

from Crypto.Cipher import DES3
from pathlib import Path
from datetime import datetime

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

def setup_logging(verbose=False):
    # create logger
    logger = logging.getLogger("pulse_meter")
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)

    # If handler already exists, don't add another one
    if logger.handlers:
        return logger

    # create console handler with proper log level
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG if verbose else logging.INFO)
    ch.setFormatter(CustomFormatter())
    logger.addHandler(ch)
    
    return logger

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
    # - parse netstat output for IOCS / malicious connections

def parse_files(snapshot, check_date=False, check_size=False, check_new=False):
    # build a dictionary of all the files in the snapshot
    snapshot_files = {}
    dir_name = '/'
    pulse_hash = None

    # find the line starting "### Output of /bin/ls -laR"
    snapshot_str = snapshot.decode('utf-8', errors='ignore')
    start_str = '### Output of /bin/ls -laR'
    ls_start = snapshot_str.find(start_str)
    if ls_start == -1:
        logger.error("Could not find file list in snapshot")
        return snapshot_files

    for line in snapshot_str[ls_start+len(start_str):].splitlines():
        if line.startswith('### End'):
            logger.info("End of file list")
            break

        if line.endswith(':'):
            # this is a directory
            dir_name = line[:-1]
            continue

        if line.startswith('total'):
            # this is a directory
            continue

        if line == '':
            # end of the directory
            continue

        # get the file size, date, and name
        match = re.match(
            r"^([\-rwx]+\.?)\s+(\d+)\s+(\w+)\s+(\w+)\s+(\d+)\s+(\w+\s+\d+\s+\d+:\d+)\s+(.+)$",
            line)

        if match:
            perms, nlinks, uid, gid, size, date, name = match.groups()
            full_path = dir_name.rstrip('/') + '/' + name
            snapshot_files[full_path] = {
                'size': int(size),
                'date': date,
            }

            # get the pulse hash
            hash_match = re.match(r"^/home/webserver/htdocs/dana-na/auth/jquery.min_([a-fA-F0-9]{64}).js$", full_path)
            if hash_match:
                pulse_hash = hash_match.group(1)
                logger.info(f"Pulse hash: {pulse_hash}")

    # finished parsing snapshot files
    # check we found the pulse hash
    if pulse_hash is None:
        logger.error("Pulse hash not found. Unable to match against manifest")
        sys.exit(1)

    # check if we have a manifest for this version
    manifest = None
    manifest_dir = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'manifest')
    for file in os.listdir(manifest_dir):
        if file.endswith('.json'):
            with open(os.path.join(manifest_dir, file), 'r') as f:
                info = json.load(f)
                if info['version']['pulse_hash'].lower() == pulse_hash.lower():
                    logger.info(f"Found manifest: {file}")
                    manifest = info
                    break

    if manifest is None:
        logger.error("No manifest found for this version")
        sys.exit(1)

    # check each file in the manifest matches the files in the snapshot
    for m_file in manifest['files']:
        if m_file not in snapshot_files:
            logger.debug(f"File {m_file} not found in snapshot")
            continue

        # This checks the size of the file in the snapshot against the manifest
        if check_size and snapshot_files[m_file]['size'] != manifest['files'][m_file]['size']:
            logger.warning(f"[Files IOC] File={m_file}, Snapshot size={snapshot_files[m_file]['size']}, " \
                f"Expected size={manifest['files'][m_file]['size']}")

        # This checks the timestamp of the file in the snapshot against the manifest
        # Note: The snapshot timestamp is relative to the timezone of the machine that took the snapshot,
        # Whereas the manifest timestamp is in UTC
        # We should get the timezone of the machine, but for now we can simply check the drift is less than X hours
        snapshot_date = datetime.strptime(snapshot_files[m_file]['date'], "%b %d %H:%M")
        manifest_date = datetime.strptime(manifest['files'][m_file]['date'], "%b %d %H:%M")
        num_seconds_drift = 12 * 60 * 60 # 12 hours
        if check_date and abs((snapshot_date - manifest_date).total_seconds()) > num_seconds_drift:
            logger.warning(f"[Files IOC] File={m_file}, Snapshot date={snapshot_files[m_file]['date']}, " \
                f"Expected date={manifest['files'][m_file]['date']}")

        logger.debug(f"File {m_file} matches")

    # This next check looks for files that are in the snapshot, but not in the manifest
    # This is slightly unreliable because some files are extracted on install,
    # or might be data files generated at runtime (e.g. temp files, logs, .pyc etc.)
    # Therefore, all this check can do is warn if a file in htdocs is not in the manifest
    # (with the exception of help files, which are ignored)
    # TODO: load these from the manifest?
    skip_files = [
        r"^/home/runtime/webserver/htdocs/dana-na/help/.*$",        # Help files
        r"^/home/runtime/webserver/htdocs/dana-cached/help/.*$",    # Help files
        r"^/home/runtime/webserver/docs/.*$",                       # Docs
        #r"^(?!/home/runtime/webserver/htdocs).*$",                 # Files not in htdocs
        r"^/home/runtime/logs/.*$",                                 # Logs
        r"^/data/var/dlogs/.*$",                                    # Logs
        r"^/home/runtime/jails/.*$",                                # Jails
        r"^/home/runtime/mtmp/.*$",                                 # Temp files
        r"^/var/tmp/.*$",                                           # Temp files
        r"^/data/var/tmp/.*$",                                      # Temp files
        r"^/data/var/runtime/tmp/.*$",                              # Temp files
        r"^/home/runtime/radius/.*$",
        r"^/home/radius/.*$",
        r"^/home/runtime/pgsql/.*$",
        r"^/home/runtime/webapplets/.*$",
        r"^/home/runtime/pids/.*$",
        r"^/home/runtime/kwatchdog/.*$",
        r"^/home/runtime/license/.*$",
        r"^/home/runtime/vercheck/.*$",
        r"^/home/runtime/esap/.*$",
        r"^/home/runtime/cluster/.*$",
        r"^/home/runtime/cockpit/.*$",
        r"^/home/runtime/dashboard/.*$",
        r"^/home/runtime/dns/.*$",
        r"^/home/runtime/etc/ssh/.*$",
        r"^/home/runtime/citus/ueba/.*$",
        r"^/home/runtime/lmdb-backup/.*$",
        r"^/home/runtime/SparkGateway/.*$",
        r"^/data/var/firstTimeBoot$",
        r"^/data/var/run/auditd.pid$",
        r"^/home/runtime/.csctx$",
        r"^/home/runtime/.distmap$",
        r"^/home/runtime/.loginfo$",
        r"^/home/runtime/.sessiongen$",
        r"^/home/runtime/.shardmap$",
        r"^/home/runtime/.statsmap$",
        r"^/home/runtime/cache_stats$",
        r"^/home/runtime/fipsmodule.cnf$",
        r"^/home/runtime/gw_net_info_actual_settings.json$",
        r"^/home/runtime/hosts.vc0$",
        r"^/home/runtime/ip.cfg$",
        r"^/home/runtime/licenseServerCertificates$",
        r"^/home/runtime/name$",
        r"^/home/runtime/network-boot-mark$",
        r"^/home/runtime/nodeState$",
        r"^/home/runtime/nodeStatistics$",
        r"^/home/runtime/nodeStatistics.old$",
        r"^/home/runtime/runlevel$",
        r"^/home/runtime/runlevel.confirmed$",
        r"^/home/runtime/snmpd.conf$",
        r"^/home/runtime/statfile$",
        r"^/home/runtime/system.j$",
        r"^/home/runtime/system.s$",
        r"^/home/runtime/cachedlocaldata/vc0/rdpAppletCounter$",
        r"^/home/runtime/dssyncdb/vc0$",
        r"^/home/runtime/webserver/conf/intermediate.crt$",
        r"^/home/runtime/webserver/conf/secure.crt$",
        r"^/home/runtime/webserver/conf/secure.key$",
        r"^/home/runtime/webserver/imgs/logo.png$",
        r"^/home/runtime/webserver/imgs/smalllogo.png$",
    ]

    if check_new:
        for s_file in snapshot_files:
            # Skip if file matches any of the skip patterns
            if any(re.match(pattern, s_file) for pattern in skip_files):
                logger.debug(f"Skipping file check for {s_file} (matches skip pattern)")
                continue
                
            if s_file not in manifest['files']:
                logger.warning(f"[Files IOC] File={s_file} not in manifest")

    # print the files
    #logger.debug("Snapshot files:")
    #for file in snapshot_files:
    #    logger.debug(f"file: {file}, size: {snapshot_files[file]['size']}, date: {snapshot_files[file]['date']}")


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
    subparsers = parser.add_subparsers(dest='action', required=True)
    
    parser.add_argument("input", help="Input file")
    parser.add_argument("-v", "--verbose", help="Verbose output", action='store_true')

    parse_parser = subparsers.add_parser('parse', help='Parse the snapshot file')
    processes_parser = subparsers.add_parser('processes', help='Parse the process list')
    
    decrypt_parser = subparsers.add_parser('decrypt', help='Decrypt the snapshot file')
    decrypt_parser.add_argument("--key", help="Key to use for decryption", required=False)
    
    files_parser = subparsers.add_parser('files', help='Parse the file list')
    files_parser.add_argument("--check-date", help="Check the file date", action='store_true')
    files_parser.add_argument("--check-size", help="Check the file size", action='store_true')
    files_parser.add_argument("--check-new", help="Check for new files", action='store_true')

    args = parser.parse_args()

    logger = setup_logging(verbose=args.verbose)

    if not os.path.exists(args.input):
        logger.error(f'Input file not found: {args.input}')
        sys.exit(1)

    if args.action == "parse":
        logger.info(f'Parsing snapshot file: {args.input}')

        with open(args.input, 'rb') as f:
            decrypted = f.read()

        parse_snapshot(decrypted)

    elif args.action == "processes":
        logger.info(f'Parsing process list from snapshot file: {args.input}')
        with open(args.input, 'rb') as f:
            decrypted = f.read()

        parse_process_list(decrypted)

    elif args.action == "files":
        logger.info(f'Parsing file list from snapshot file: {args.input}')
        with open(args.input, 'rb') as f:
            decrypted = f.read()

        parse_files(
            decrypted,
            check_date=args.check_date,
            check_size=args.check_size,
            check_new=args.check_new
            )

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
