import subprocess
import sys


def ftp_recon(ip_address, port, save_file_path, username_list, password_list):
    print("INFO: Performing nmap FTP script scan for {ip}:{port".format(ip=ip_address, port=port))
    ftp_scan = "nmap -sV -Pn -vv -p {port} --script=ftp-anon,ftp-bounce,ftp-libopie,ftp-proftpd-backdoor," \
               "ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221 -oN '{save_file_path}/{ip}_ftp.nmap' {ip}". \
        format(port=port, save_file_path=save_file_path,ip=ip_address)
    results = subprocess.check_output(ftp_scan, shell=True)
    outfile = "{save_file_path}/{ip}_ftprecon.txt".format(save_file_path=save_file_path)
    f = open(outfile, "w")
    f.write(results)
    f.close()

    print("INFO: Performing hydra ftp scan against {ip}".format(ip=ip_address))
    hydra = "hydra -L {username_list} -P {password_list} -f " \
            "-o {save_file_path}/{ip}_ftphydra.txt -u {ip} -s {port} ftp".format(username_list=username_list,
                                                                                 password_list=password_list,
                                                                                 save_file_path=save_file_path,
                                                                                 ip=ip_address,
                                                                                 port=port)
    results = subprocess.check_output(hydra, shell=True)
    resultarr = results.split(b'\n')
    for result in resultarr:
        if "login:" in result:
            print("[*] Valid ftp credentials found: {result}".format(result=result))


if __name__ == "__main__":
    if len(sys.argv) != 5:
        print("Usage: ftprecon.py <ip address> <port> <save_file_path> <usernames_list> <password_list>")
        sys.exit(0)
    ftp_recon(ip_address=sys.argv[1].strip(), port=sys.argv[2].strip(), save_file_path=sys.argv[3],
              username_list=sys.argv[4], password_list=sys.argv[5])
