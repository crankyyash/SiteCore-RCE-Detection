import requests
import sys
import getopt
import re
import xml.etree.ElementTree as ET
from urllib3.exceptions import InsecureRequestWarning

#Script to check sitecore version and whether its vulnerable to Pre-Auth RCE - CVE-2021-42237

def main(argv):
    inputfile = ""
    try:
        opts, args = getopt.getopt(argv[1:],"hi:",["help","ifile="])
    except getopt.GetoptError:
        print('checkforsitecore.py -i <inputfile>')
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print('test.py -i <inputfile>')
            sys.exit()
        elif opt in ("-i", "--ifile"):
            inputfile = arg
    run(inputfile)

def run(inputfile):
    print(inputfile)
    requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
    url1 = "/sitecore/shell/ClientBin/Reporting/Report.ashx"
    url2 = "/sitecore/shell/sitecore.version.xml"
    f = open(inputfile,'r')
    data = '<?xml version="1.0" ?><a></a>'
    lines = f.readlines()
    for i in lines:
        try:
            print(f"URL : {i.strip()}")
            url3 = "https://" + i.strip() + url2;
            print(f"[+] Checking sitecore version at {url3} :")
            x = requests.get(url3, verify = False)
            if x.status_code == 200 and re.findall("Sitecore Corporation",x.text):
                root = ET.fromstring(x.content)
                title = root[2].text
                date = root[1].text
                #print(title)
                version = root[0][0].text + "." + root[0][1].text + "." + root[0][3].text
                #print(version)
                #print("\r\n")
                print(f"Sitecore version : {title} {version} dated {date}")
                url4 = "https://" + i.strip() + url1
                print(f"[+]making get request to {url4} :")
                r1 = requests.get(url4)
                print("[+]status code:")
                print(r1.status_code)
                if r1.status_code == 200:
                    print(f"[+] Possible SiteCore RCE here! Visit {url4} to confirm")
                print(f"[+]making post request to {url4} :")
                r2 = requests.post(url4,data)
                print(f"{r2.status_code}\r\n")
                if r2.status_code == 200:
                    print(f"[+] Possible SiteCore RCE here! Visit {url4} to confirm")
            elif x.status_code == 301:
                print(f"[-] Redirected! No Sitecore here at {i.strip()}\r\n")
            else:
                print(f"[-] No Sitecore here at {i.strip()}\r\n")
        except requests.exceptions.ConnectionError:
            print("[-]Some connection error. Moving on.\r\n")
            continue
        except requests.exceptions.Timeout:
            print("[-]Some timeout error. Moving on.\r\n")
            continue
    f.close()

if __name__ == "__main__":
    main(sys.argv)