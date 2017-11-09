Spawned from Mike Czumak (@SecuritySift)'s scripts, these modified versions allow for multiple command line options.

Some of these new command line options include:
* --ips: A list of IPs to scan.  This list can be separated by comma or space.
* --ip_file: A file containing IPs separated by new line.
* --nmap_scan_full: A full TCP/UDP scan of the hosts
* --nmap_scan_top20: A TCP/UDP scan for the Top 20 ports.
* --log_dir: Directory where to store the output files.  Will be created if it doesn't exist.
* --fuzzdb_path: Path to the FuzzDB on the local machine (https://github.com/fuzzdb-project/fuzzdb.git)
* --usernames: A list of usernames to try when credential guessing
* --passwords:  A list of passwords to try when credential guessing.
