#!/usr/bin/env python

# [Title]: reconscan.py -- a recon/enumeration script
# [Author]: Mike Czumak (T_v3rn1x) -- @SecuritySift
# [Modified By]: ProgrammerChad
#
# [Details]:
# This script is intended to be executed remotely against a list of IPs to enumerate discovered services such
# as smb, smtp, snmp, ftp and other.  The core logic is the same as @SecuritySift's work, but I added several
# helpful command line arguments that were helpful to me.

import argparse
import multiprocessing
import os
import subprocess
from multiprocessing import Process


def multi_proc(process=None, ip_address=None, port=None, save_file_path=None, fuzzdb_path=None, usernames=None,
               passwords=None):
    jobs = []
    p = multiprocessing.Process(target=process, args=(ip_address, port, save_file_path, fuzzdb_path, usernames,
                                                      passwords))
    jobs.append(p)
    p.start()
    return


def dns_enum(ip_address=None, port=None, save_file_path=None, fuzzdb_path=None, usernames=None, passwords=None):
    print("INFO: Detected DNS on {ip}:{port}".format(ip=ip_address, port=port))
    if port.strip() == "53":
        script = "python dnsrecon.py {ip}".format(ip=ip_address)  # execute the python script
        subprocess.call(script, shell=True)
    return


def http_enum(ip_address=None, port=None, save_file_path=None, fuzzdb_path=None, usernames=None, passwords=None):
    print("INFO: Detected http on {ip}:{port}".format(ip=ip_address, port=port))
    print("INFO: Performing nmap web script scan for {ip}:{port}".format(ip=ip_address, port=port))
    http_scan = "nmap -sV -Pn -vv -p {port} --script=http-vhosts,http-userdir-enum,http-apache-negotiation," \
                "http-backup-finder,http-config-backup,http-default-accounts,http-email-harvest,http-methods," \
                "http-method-tamper,http-passwd,http-robots.txt -oN " \
                "{save_file_path}/{ip}_http.nmap {ip}".format(port=port, ip=ip_address, save_file_path=save_file_path)
    subprocess.check_output(http_scan, shell=True)
    dir_bust = "python dirbust.py http://{ip}:{port} {ip} {save_file_path}".format(ip=ip_address, port=port,
                                                                                   save_file_path=save_file_path)
    subprocess.call(dir_bust, shell=True)


def https_enum(ip_address=None, port=None, save_file_path=None, fuzzdb_path=None, usernames=None, passwords=None):
    print("INFO: Detected http on {ip}:{port}".format(ip=ip_address, port=port))
    print("INFO: Performing nmap web script scan for {ip}:{port}".format(ip=ip_address, port=port))
    https_scan = "nmap -sV -Pn -vv -p {port} --script=http-vhosts,http-userdir-enum,http-apache-negotiation," \
                 "http-backup-finder,http-config-backup,http-default-accounts,http-email-harvest,http-methods," \
                 "http-method-tamper,http-passwd,http-robots.txt -oX " \
                 "{save_file_path}/{ip}_https.nmap {ip}".format(port=port, ip=ip_address, save_file_path=save_file_path)
    subprocess.check_output(https_scan, shell=True)
    dir_bust = "python dirbust.py https://{ip}:{port} {ip} {save_file_path}".format(ip=ip_address, port=port,
                                                                                    save_file_path=save_file_path)
    subprocess.call(dir_bust, shell=True)


def mssql_enum(ip_address=None, port=None, save_file_path=None, fuzzdb_path=None, usernames=None, passwords=None):
    print("INFO: Detected MS-SQL on {ip}:{port}".format(ip=ip_address, port=port))
    print("INFO: Performing nmap mssql script scan for {ip}:{port}".format(ip=ip_address, port=port))
    mssql_scan = "nmap -vv -sV -Pn -p {port} --script=ms-sql-info,ms-sql-config,ms-sql-dump-hashes " \
                 "--script-args=mssql.instance-port=1433,smsql.username-sa,mssql.password-sa -oX " \
                 "{save_file_path}/{ip}_mssql.xml {ip}".format(port=port, ip=ip_address, save_file_path=save_file_path)
    subprocess.check_output(mssql_scan, shell=True)


def ssh_enum(ip_address=None, port=None, save_file_path=None, fuzzdb_path=None, usernames=None, passwords=None):
    print("INFO: Detected SSH on {ip}:{port}".format(ip=ip_address, port=port))
    script = "python sshrecon.py {ip} {port} {save_file_path} {usernames} {passwords}". \
        format(ip=ip_address, port=port, save_file_path=save_file_path, usernames=usernames, passwords=passwords)
    subprocess.call(script, shell=True)


def snmp_enum(ip_address=None, port=None, save_file_path=None, fuzzdb_path=None, usernames=None, passwords=None):
    output = "INFO: Detected snmp on {ip}:{port}".format(ip=ip_address, port=port)
    print("INFO: Detected snmp on {ip}:{port}".format(ip=ip_address, port=port))
    script = "python snmprecon.py {ip}".format(ip=ip_address)
    output += subprocess.check_output(script, stderr=subprocess.STDOUT, shell=True)
    f = open("{save_file_path}/{ip}_snmprecon.txt".format(ip=ip_address, save_file_path=save_file_path), "w")
    f.write(output)
    f.close()


def smtp_enum(ip_address=None, port=None, save_file_path=None, fuzzdb_path=None, usernames=None, passwords=None):
    output = "INFO: Detected smtp on {ip}:{port}".format(ip=ip_address, port=port)
    print("INFO: Detected smtp on {ip}:{port}".format(ip=ip_address, port=port))
    if port.strip() == "25":
        script = "python smtprecon.py {ip} {fuzzdb_path}".format(ip=ip_address, fuzzdb_path=fuzzdb_path)
        output += subprocess.check_output(script, stderr=subprocess.STDOUT, shell=True)
    else:
        output += "WARNING: SMTP detected on non-standard port, smtprecon skipped (must run manually)"
        print("WARNING: SMTP detected on non-standard port, smtprecon skipped (must run manually)")
    f = open('{save_file_path}/{ip}_smtp_recon.txt'.format(save_file_path=save_file_path, ip=ip_address), 'w')
    f.write(output)
    f.close()


def smb_enum(ip_address=None, port=None, save_file_path=None, fuzzdb_path=None, usernames=None, passwords=None):
    output = "INFO: Detected SMB on {ip}:{port}".format(ip=ip_address, port=port)
    print("INFO: Detected SMB on {ip}:{port}".format(ip=ip_address, port=port))
    if port.strip() == "445":
        script = "python smbrecon.py {ip} 2>/dev/null".format(ip=ip_address)
        output += subprocess.check_output(script, stderr=subprocess.STDOUT, shell=True)
    else:
        output += "WARNING: SMB detected on non-standard port, smbrecon skipped (must run manually)"
        print("WARNING: SMB detected on non-standard port, smbrecon skipped (must run manually)")
    f = open('{save_file_path}/{ip}_smb_recon.txt'.format(save_file_path=save_file_path, ip=ip_address), 'w')
    f.write(output)
    f.close()


def ftp_enum(ip_address=None, port=None, save_file_path=None, fuzzdb_path=None, usernames=None, passwords=None):
    print("INFO: Detected ftp on {ip}:{port}".format(ip=ip_address, port=port))
    script = "python ftprecon.py {ip} {port} {save_file_path} {usernames_list} {password_list}".format(ip=ip_address,
                                                                                                       port=port,
                                                                                                       save_file_path=
                                                                                                       save_file_path,
                                                                                                       usernames_list=
                                                                                                       usernames,
                                                                                                       password_list=
                                                                                                       passwords)
    subprocess.call(script, shell=True)


def nmap_scan(ip_address, scan_type, log_dir, fuzzdb_path, usernames, passwords):
    ip_address = ip_address.strip()
    save_file_path = os.path.join(log_dir, ip_address)
    subprocess.check_output("mkdir -p {save_file_path}".format(save_file_path=save_file_path), shell=True)
    print("INFO: Running general TCP/UDP nmap scans for {ip}".format(ip=ip_address))
    serv_dict = {}
    if scan_type == "FULL":
        tcp_scan = "nmap -vv -Pn -A -sC -sS -T 4 -p- -oN '{save_file_path}.nmap' " \
                   "-oX '{save_file_path}/{ip}_nmap_scan_import.xml' {ip}".format(save_file_path=save_file_path,
                                                                                  ip=ip_address)
        udp_scan = "nmap -vv -Pn -A -sC -sU -T 4 --top-ports 200 -oN '{save_file_path}U.nmap' " \
                   "-oX '{save_file_path}/{ip}U_nmap_scan_import.xml' {ip}".format(save_file_path=save_file_path,
                                                                                   ip=ip_address)
    elif scan_type == "TOP20":
        tcp_scan = "nmap -sT {ip} --top-ports 20 -oN {save_file_path}/{ip}.nmap " \
                   "-oX {save_file_path}/{ip}_nmap_scan_import.xml".format(save_file_path=save_file_path, ip=ip_address)
        udp_scan = "nmap -sU {ip} --top-ports 20 -oN {save_file_path}/{ip}U.nmap " \
                   "-oX {save_file_path}/{ip}U_nmap_scan_import.xml".format(save_file_path=save_file_path,
                                                                            ip=ip_address)

    results = subprocess.check_output(tcp_scan, shell=True)
    udp_results = subprocess.check_output(udp_scan, shell=True)
    lines = results.split("\n")
    for line in lines:
        ports = []
        line = line.strip()
        if ("tcp" in line) and ("open" in line) and not ("Discovered" in line):
            while "  " in line:
                line = line.replace("  ", " ");
            linesplit = line.split(" ")
            service = linesplit[2]  # grab the service name
            port = line.split(" ")[0]  # grab the port/proto
            if service in serv_dict:
                ports = serv_dict[service]  # if the service is already in the dict, grab the port list

            ports.append(port)
            serv_dict[service] = ports  # add service to the dictionary along with the associated port(2)

    # go through the service dictionary to call additional targeted enumeration functions
    for serv in serv_dict:
        ports = serv_dict[serv]
        if serv == "http":
            for port in ports:
                port = port.split("/")[0]
                multi_proc(process=http_enum, ip_address=ip_address, port=port, save_file_path=save_file_path)
        elif (serv == "ssl/http") or ("https" in serv):
            for port in ports:
                port = port.split("/")[0]
                multi_proc(process=https_enum, ip_address=ip_address, port=port, save_file_path=save_file_path)
        elif "ssh" in serv:
            for port in ports:
                port = port.split("/")[0]
                multi_proc(process=ssh_enum, ip_address=ip_address, port=port, save_file_path=save_file_path,
                           usernames=usernames, passwords=passwords)
        elif "smtp" in serv:
            for port in ports:
                port = port.split("/")[0]
                multi_proc(process=smtp_enum, ip_address=ip_address, port=port, save_file_path=save_file_path,
                           fuzzdb_path=fuzzdb_path)
        elif "snmp" in serv:
            for port in ports:
                port = port.split("/")[0]
                multi_proc(process=snmp_enum, ip_address=ip_address, port=port, save_file_path=save_file_path)
        elif "domain" in serv:
            for port in ports:
                port = port.split("/")[0]
                multi_proc(process=dns_enum, ip_address=ip_address, port=port, save_file_path=save_file_path)
        elif "ftp" in serv:
            for port in ports:
                port = port.split("/")[0]
                multi_proc(process=ftp_enum, ip_address=ip_address, port=port, save_file_path=save_file_path,
                           usernames=usernames, passwords=passwords)
        elif "microsoft-ds" in serv:
            for port in ports:
                port = port.split("/")[0]
                multi_proc(process=smb_enum, ip_address=ip_address, port=port, save_file_path=save_file_path)
        elif "ms-sql" in serv:
            for port in ports:
                port = port.split("/")[0]
                multi_proc(process=mssql_enum, ip_address=ip_address, port=port, save_file_path=save_file_path)
    exit("INFO: TCP/UDP Nmap scans completed for {ip}".format(ip=ip_address))


# grab the discover scan results and start scanning up hosts
print("############################################################")
print("####                      RECON SCAN                    ####")
print("####            A multi-process service scanner         ####")
print("####        http, ftp, dns, ssh, snmp, smtp, ms-sql     ####")
print("############################################################")

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    ips = parser.add_mutually_exclusive_group(required=True)
    ips.add_argument('--ips', help='IPs to Scan')
    ips.add_argument('--ip_file', help='File containing a list of IPs to scan.')
    nmap_scan_type = parser.add_mutually_exclusive_group(required=True)
    nmap_scan_type.add_argument('--nmap_scan_full', help="Full NMAP TCP/UDP scan", action='store_true')
    nmap_scan_type.add_argument('--nmap_scan_top20', help="Top 20 Ports NMAP TCP/UDP scan", action='store_true')
    parser.add_argument('--log_dir', help="Directory to store results.", default="/tmp")
    parser.add_argument('--fuzzdb_path', help="Path to FuzzDB Wordlists",
                        default='/usr/share/wfuzz/wordlist/fuzzdb')
    parser.add_argument('--usernames', help="Username wordlists",
                        default="/usr/share/wfuzz/wordlist/fuzzdb/wordlists-user-passwd/names/namelist.txt")
    parser.add_argument('--passwords', help="Password wordlists",
                        default="/usr/share/wfuzz/wordlist/fuzzdb/wordlists-user-passwd/names/namelist.txt")
    args = parser.parse_args()

    if args.ips:
        if "," in args.ips:
            ips = [ip.strip() for ip in args.ips.split(',')]
        else:
            ips = [ip.strip() for ip in args.ips.split(' ')]
    elif args.ip_file:
        ips = open(args.ip_file, 'r')

    # NMAP Scan Type defaults to TOP20
    scan_type = "TOP20"
    if args.nmap_scan_full:
        scan_type = "FULL"
    elif args.nmap_scan_top20:
        scan_type = "TOP20"

    for scan_ip in ips:
        jobs = []
        p = multiprocessing.Process(target=nmap_scan, args=(scan_ip, scan_type, args.log_dir, args.fuzzdb_path,
                                                            args.usernames, args.passwords,))
        jobs.append(p)
        p.start()
