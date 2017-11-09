import sys
import subprocess

ERRORS = ["STATUS_ACCESS_DENIED", "STATUS_REQUEST_NOT_ACCEPTED", "Connection refused", "Connect error",
          "Connection reset"]


def smb_recon(ip_address):
    nbt_scan = "/usr/bin/impacket-samrdump {ip}".format(ip=ip_address)
    nbtresults = subprocess.check_output(nbt_scan, stderr=subprocess.STDOUT, shell=True)
    error = [x for x in ERRORS if x in nbtresults]
    if not error:
        print("[*] SAMRDUMP User accounts/domains found on {ip}".format(ip=ip_address))
        output = "[*] SAMRDUMP User accounts/domains found on {ip}".format(ip=ip_address)
        lines = nbtresults.split(b"\n")
        for line in lines:
            if ("Found" in line) or (" . " in line):
                print("   [+] {line}".format(line=line))
                output += "   [+] {line}".format(line=line)
    else:
        print("[!!] Connection error when attempting to connect to {ip}: {error}".format(ip=ip_address, error=error[0]))
        output = "[!!] Connection error when attempting to connect to {ip}: {error}".format(ip=ip_address,
                                                                                            error=error[0])
    return output


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: smbrecon.py <ip address>")
        sys.exit(0)
    smb_recon(ip_address=sys.argv[1])
