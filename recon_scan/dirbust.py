import sys
import os
import subprocess


def dir_bust(url, scan_name, save_file_path):
    folders = ["/usr/share/dirb/wordlists", "/usr/share/dirb/wordlists/vulns"]
    found = []

    for folder in folders:
        for filename in os.listdir(folder):
            print("INFO: Starting dirb scan for {url}: {filename}".format(url=url, filename=filename))
            outfile = " -o {save_file_path}/{name}_dirb_{filename}".format(save_file_path=save_file_path,
                                                                           name=scan_name,
                                                                           filename=filename)
            dirb_scan = "dirb {url} {folder}/{filename} {outfile} -S -r".format(url=url, folder=folder,
                                                                                filename=filename, outfile=outfile)
            try:
                results = subprocess.check_output(dirb_scan, shell=True)
                resultarr = results.split(b"\n")
                for line in resultarr:
                    if "+" in line:
                        if line not in found:
                            found.append(line)
            except:
                pass

            try:
                if found[0] != "":
                    print("[*] Dirb found the following items on {url} from: {filename}".format(url=url,
                                                                                                filename=filename))
                    for item in found:
                        print("   {item}".format(item=item))
            except:
                print("INFO: No items found during dirb scan of {url}: {filename}".format(url=url, filename=filename))


if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: dirbust.py <target url> <scan name> <save_file_path> ")
        sys.exit(0)
    dir_bust(url=sys.argv[1], scan_name=sys.argv[2], save_file_path=sys.argv[3])
