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

def parse_files(snapshot, check_date=False, check_size=False, check_new=False, list_files=False):
    # build a dictionary of all the files in the snapshot
    snapshot_files = {}
    dir_name = '/'
    pulse_hash = None

    snapshot_str = snapshot.decode('utf-8', errors='ignore')

    # Get date from snapshot header
    first_line = snapshot_str[:snapshot_str.find('\n')]
    date_match = re.search(r'System state snapshot created (\w+ \w+ \d{2} \d{2}:\d{2}:\d{2} \d{4})', first_line)
    if date_match:
        snapshot_created = datetime.strptime(date_match.group(1), "%a %b %d %H:%M:%S %Y")
    else:
        logger.error("Could not find snapshot date in snapshot header")
        sys.exit(1)

    # find the line starting "### Output of /bin/ls -laR"
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

        # get the file size, date, and name (and symlink target if present)
        match = re.match(r"^([dl-][rwx-]+\.?)\s+(\d+)\s+(\w+)\s+(\w+)\s+(\d+)\s+(\w+\s+\d+\s+(?:\d{4}|\d{2}:\d{2}))\s+(.+?)(?: -> (.+))?$", line)

        if match:
            perms, nlinks, uid, gid, size, date, name, target = match.groups()
            if name == '.' or name == '..':
                continue

            # skip directories
            if perms.startswith('d'):
                continue

            full_path = dir_name.rstrip('/') + '/' + name

            snapshot_files[full_path] = {
                'size': int(size),
                'date': date,
                'symlink': target if target else None,
                'perms': perms
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
    for m_file, m_info in manifest['files'].items():
        if m_file not in snapshot_files:
            logger.debug(f"File {m_file} not found in snapshot")
            continue
            
        # Check if symlink points to expected target
        if 'symlink' in m_info:
            if not snapshot_files[m_file]['symlink']:
                logger.warning(f"[Files IOC] File={m_file} should be a symlink to {m_info['symlink']}")
            elif snapshot_files[m_file]['symlink'] != m_info['symlink']:
                logger.warning(f"[Files IOC] File={m_file} symlinks to {snapshot_files[m_file]['symlink']}, " \
                    f"expected {m_info['symlink']}")
            continue  # Skip size/date checks for symlinks
        
        elif snapshot_files[m_file]['symlink']:
            # File is a symlink in snapshot but not in manifest
            # Try checking the snapshot symlink's target instead
            resolved = resolve_symlink(snapshot_files, m_file)
            if resolved:
                logger.debug(f"Resolved symlink target: {resolved}")
                # Compare the resolved symlink target
                m_file = resolved

        # Simple direct comparison - no symlink resolution needed
        if check_size and snapshot_files[m_file]['size'] != m_info['size']:
            logger.warning(f"[Files IOC] File={m_file}, " \
                f"Snapshot size={snapshot_files[m_file]['size']}, " \
                f"Expected size={m_info['size']}")

            # Potential false positives:
            # /home/config/snmpd.spec.cfg

        # This checks the timestamp of the file in the snapshot against the manifest
        # Note: The snapshot timestamp is relative to the timezone of the machine that took the snapshot.
        # Whereas the manifest timestamp is in UTC
        # We also need to account HH:MM precision loss in the snapshot for timestamps with no time
        # These are rounded down to 00:00, so we need to allow for 24 hours of drift there too.
        try:
            snapshot_date = datetime.strptime(snapshot_files[m_file]['date'], "%b %d %H:%M")
            # If timestamp has no year, use current year but adjust if that would make it future
            snapshot_year = snapshot_created.year
            snapshot_date = snapshot_date.replace(year=snapshot_year)
            
            # If this makes the date in the future, it must be from last year
            if snapshot_date > snapshot_created:
                snapshot_date = snapshot_date.replace(year=snapshot_year - 1)
                
            # For HH:MM format, use standard timezone drift
            # UTC+14 (e.g., Line Islands) to UTC-14 (e.g., Baker Island)
            # So total possible drift is 14 hours in either direction
            max_drift = 14 * 60 * 60  # Max timezone difference from UTC (±14 hours)
                
        except ValueError:
            # This format has just the date (no time), so could be anywhere in that 24 hour period
            snapshot_date = datetime.strptime(snapshot_files[m_file]['date'], "%b %d %Y")
            # For date-only format, allow for:
            # - 24 hours for time precision (could be 23:59:59)
            # - ±14 hours for timezone difference from UTC
            max_drift = (24 + 14) * 60 * 60  # 24 hours for time precision + max timezone difference

        manifest_date = datetime.strptime(m_info['date'], "%Y-%m-%dT%H:%M:%SZ")

        # abs() handles both positive and negative timezone differences
        if check_date and abs((snapshot_date - manifest_date).total_seconds()) > max_drift:
            logger.warning(f"[Files IOC] File={m_file}, " \
                f"Snapshot date={snapshot_date}, " \
                f"Expected date={manifest_date}")

    # This next check looks for files that are in the snapshot, but not in the manifest
    # This is slightly unreliable because some files are extracted on install,
    # or might be data files generated at runtime (e.g. temp files, logs, .pyc etc.)
    # TODO: load these from the manifest so they are firmware version specific
    # NOTE: if you want to see these files in the output, run with --verbose
    data_files = [
        r"^/home/runtime/webserver/docs/.*\.msg(\.(de|fr|ja|pt|zh))?$", # Docs
        r"^/home/runtime/logs/.*$",                                     # Logs
        r"^/data/var/dlogs/.*$",                                        # Logs
        r"^/home/runtime/jails/.*$",                                    # Jails
        r"^/home/runtime/mtmp/.*$",                                     # Temp files
        r"^/var/tmp/.*$",                                               # Temp files (we should check here for stuff like /tmp/.t)
        r"^/data/var/tmp/.*$",                                          # Temp files
        r"^/data/var/runtime/tmp/.*$",                                  # Temp files
        r"^/home/radius/\d{8}\.act$",                                   # Radius
        r"^/home/radius/acthdr\.dat$",
        r"^/home/radius/radius\.pid$",
        r"^/home/runtime/radius/vendor\.ini$",
        r"^/home/runtime/radius/dictiona\.dcm$",
        r"^/home/runtime/pgsql/postgres\.uid$",
        r"^/home/runtime/pgsql/postgresd\.log$",
        r"^/home/runtime/pgsql/\.s\.PGSQL\.\d+\.lock$",
        r"^/home/runtime/webapplets/vc0/(rewritten|original)/.*$",
        r"^/home/runtime/pids/.*\.pid$",
        r"^/home/runtime/kwatchdog/watchdog\.conf$",
        r"^/home/runtime/license/.*\.(tbl|db)$",
        r"^/home/runtime/license/namedusers$",
        r"^/home/runtime/vercheck/\d{4}-\d{2}-\d{2}$",
        r"^/home/runtime/esap/packages/.*\.(pkg|xml|zip)$",
        r"^/home/runtime/esap/packages/.*cmatrix$",
        r"^/home/runtime/cluster/(clusterSignature|hosts|info)$",
        r"^/home/runtime/cluster/spread/spread-conf(-used)?$",
        r"^/home/runtime/cockpit/.*\.rrd$",
        r"^/home/runtime/cockpit/(dashboardCounters|ivsStatistics)$",
        r"^/home/runtime/dashboard/dashboard\.db(-shm|-wal)?$",
        r"^/home/runtime/dns/cache\d?$",
        r"^/home/runtime/etc/ssh/ssh_host_(rsa|dsa)_key(\.pub)?$",
        r"^/home/runtime/etc/ssh/sshd_config$",
        r"^/home/runtime/citus/ueba/pg_dist_.*\.csv$",
        r"^/home/runtime/lmdb-backup/.*(\.j|\.mdb)$",
        r"^/home/runtime/SparkGateway/gateway.conf$",
        r"^/home/runtime/SparkGateway/logs/gateway.log.0(\.lck)?$",
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
            # Skip if file matches any of the data files
            if any(re.match(pattern, s_file) for pattern in data_files):
                logger.debug(f"Skipping file check for {s_file} (matches data file pattern)")
                continue

            if snapshot_files[s_file]['symlink']:
                # Skip symlinks
                continue
                
            if s_file not in manifest['files']:
                logger.critical(f"[Files IOC] File={s_file} not in manifest")

    # print the files
    if list_files:
        logger.info("Snapshot files:")
        for file in snapshot_files:
            logger.info(f"file: {file}, size: {snapshot_files[file]['size']}, date: {snapshot_files[file]['date']}")


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

def resolve_symlink(snapshot_files, file_path):
    visited = set()  # Track visited paths to prevent infinite loops
    current_path = file_path
    
    while current_path in snapshot_files and snapshot_files[current_path]['symlink']:
        if current_path in visited:
            logger.warning(f"Symlink loop detected for {file_path}")
            return None
        visited.add(current_path)
        
        # Get the target path, handling both absolute and relative paths
        target = snapshot_files[current_path]['symlink']
        if not target.startswith('/'):
            # Convert relative path to absolute
            base_dir = os.path.dirname(current_path)
            target = '/' + os.path.normpath(os.path.join(base_dir, target)).replace('\\', '/').lstrip('/')
        
        # Handle /data/runtime -> /home/runtime path mapping
        if target.startswith('/data/runtime/'):
            target = target.replace('/data/runtime/', '/home/runtime/', 1)
        
        if target not in snapshot_files:
            logger.warning(f"Symlink target not found in snapshot: {target}")
            return None
            
        current_path = target
    
    return current_path

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
    files_parser.add_argument("--check-all", help="Run all checks", action='store_true')

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

        if args.check_all:
            args.check_date = True
            args.check_size = True
            args.check_new = True

        with open(args.input, 'rb') as f:
            decrypted = f.read()

        parse_files(
            decrypted,
            check_date=args.check_date,
            check_size=args.check_size,
            check_new=args.check_new,
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
