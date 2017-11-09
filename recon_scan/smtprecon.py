import os
import socket
import sys


# smtprecon.py uses the FuzzDB namelist, which can be cloned from: https://github.com/fuzzdb-project/fuzzdb.git

def smtp_recon(ip_address, fuzzdb_path="/usr/share/wfuzz/wordlist/fuzzdb"):
    output = ""
    print("INFO: Trying SMTP Enum on {ip}".format(ip=ip_address))
    namelist = os.path.join(fuzzdb_path, "wordlists-user-passwd/names/namelist.txt")
    try:
        names = open(namelist, 'r')
    except FileNotFoundError:
        sys.exit("{namelist} not found!".format(namelist=namelist))
    for name in names:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((sys.argv[1], 25))
        s.recv(1024)
        s.send('HELO test@test.org \r\n')
        s.recv(1024)
        s.send('VRFY ' + name.strip() + '\r\n')
        result = s.recv(1024)
        if ("not implemented" in result) or ("disallowed" in result):
            sys.exit("INFO: VRFY Command not implemented on {ip}".format(ip=sys.argv[1]))
            output += "INFO: VRFY Command not implemented on {ip}".format(ip=sys.argv[1])
        if ("250" in result) or ("252" in result) and ("Cannot VRFY" not in result):
            print("[*] SMTP VRFY Account found on {ip}: {name}".format(ip=sys.argv[1], name=name.strip()))
            output += "[*] SMTP VRFY Account found on {ip}: {name}".format(ip=sys.argv[1], name=name.strip())
        s.close()
    if output:
        return output


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: smtprecon.py <ip address> <fuzzdb_path>")
        sys.exit(0)
    smtp_recon(ip_address=sys.argv[1], fuzzdb_path=sys.argv[2])
