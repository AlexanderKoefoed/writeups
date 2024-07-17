# Authentication vulnerabilities

This writeup covers the learning path *Authentication vulnerabilities* on Portswigger.

## What is Authentication

Authentication is the process of verifying the identity of a user. Authentication can be done in 3 ways:

- A user authenticates with *something the user knows*. Like a password or answer to a security question
- A user authenticates with *something they have*. This could be security token or authenticator device
- A user authenticates with *something they do or are*. This could biometrics or patterns of behavior.

Often more than one method is used, it then becomes multi-factor authentication.

## How do authentication vulnerabilities arise?

Authentication vulns commonly occur due to:

- Flawed brute force protection
- Logic flaws or poor coding allows an attacker to bypass the authentication

Authentication is always security critical, while logic flaws in other places on website might not pose a threat, it almost always does in authentication.

One big threat is an attacker gaining access to internal services which may not be protected in the same way as web facing services, allowing the attacker access to a larger attack surface.

## Vulnerabilities in password-based login

Brute force attacks are often used by attackers when only a password is required for authentication. Fortunately protection for brute force attemps do exist, not without flaws however.

During an audit it can be beneficial to view the HTTP requests to see if any usernames or emails are disclosed when browsing a site.

Passwords can be guessed using OSINT, common logic and human predicability. Users often try to conform a password into the policies enforced upon it, changing minor things like adding a `!`. If users have to change their password regularly, they will often make small predictable changes like going from `password! --> password?`.

Attackers can perform username generation by observing the websites behavior when signing up for a new account. If the response informs the attacker that the username is already taken, he can add that username to his list. Other beneficial approaches are:

- Status codes. Different status codes can indicate correct usernames or emails.
- Error messages. Sometimes error messages can differ if the username is correct (can be other cases too)
- Response times can be different when the username is correct, the backend often has to do a extra DB query or comparison of passwords taking more time to return a response. The difference in response time is probably very small.

## Lab: Username enumeration via subtly different responses

**Lab Description**:  This lab is subtly vulnerable to username enumeration and password brute-force attacks. It has an account with a predictable username and password, which can be found in the following wordlists:

    Candidate usernames
    Candidate passwords

To solve the lab, enumerate a valid username, brute-force this user's password, then access their account page.

### Lab solution
