import subprocess
import sys


def dns_recon(ip_address, save_file_path):
    hostname = "nmblookup -A {ip} | grep '<00>' | grep -v '<GROUP>' | cut -d' ' -f1".format(ip=ip_address)
    host = subprocess.check_output(hostname, shell=True).strip()
    print("INFO: Attempting Domain Transfer on {host}".format(host=host))
    zt = "dig @{host}.thinc.local thinc.local axfr".format(host=host)
    ztresults = subprocess.check_output(zt, shell=True)
    if "failed" in ztresults:
        print("INFO: Zone Transfer failed for {host}".format(host=host))
    else:
        print("[*] Zone Transfer successful for {host} ({ip})!!! [see output file]".format(host=host, ip=ip_address))
        outfile = "{save_file_path}/{ip}_zonetransfer.txt".format(ip=ip_address, save_file_path=save_file_path)
        dnsf = open(outfile, "w")
        dnsf.write(ztresults)
        dnsf.close()


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: dnsrecon.py <ip address> <save_file_path>")
        sys.exit(0)
    dns_recon(ip_address=sys.argv[1], save_file_path=sys.argv[2])
