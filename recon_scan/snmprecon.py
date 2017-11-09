import subprocess
import sys


def snmp_recon(ip_address):
    snmpdetect = 0

    one_six_one_scan = "onesixtyone {ip}".format(ip=ip_address)
    results = subprocess.check_output(one_six_one_scan, shell=True).strip()

    if results != "":
        if "Windows" in results:
            results += results.split("Software: ")[1]
            snmpdetect = 1
        elif "Linux" in results:
            results += results.split("[public] ")[1]
            snmpdetect = 1
        if snmpdetect == 1:
            print("[*] SNMP running on {ip}; OS Detect: {results}".format(ip=ip_address, results=results))
            snmp_walk = "snmpwalk -c public -v1 {ip} 1".format(ip=ip_address)
            results += subprocess.check_output(snmp_walk, stderr=subprocess.STDOUT, shell=True)

    nmap_scan = "nmap -vv -sV -sU -Pn -p 161,162 --script=snmp-netstat,snmp-processes {ip}".format(ip=ip_address)
    results += subprocess.check_output(nmap_scan, stderr=subprocess.STDOUT, shell=True)
    if results:
        return results


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: snmprecon.py <ip address>")
        sys.exit(0)
    snmp_recon(ip_address=sys.argv[1])
