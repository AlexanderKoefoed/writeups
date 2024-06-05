# Lab: Password reset broken logic

This lab's password reset functionality is vulnerable. To solve the lab, reset Carlos's password then log in and access his "My account" page.

- Your credentials: *wiener:peter*
- Victim's username: *carlos*

**Difficulty**: Apprentice

## Lab solution

Looking at the reset password functionality the requests body consists of the following form data: `username=wiener`. This means we can send an email with a reset link for an arbitrary account which we know the name of. Of course we don't have access to `carlos` email. Lets take a look at the change email function. Changing the e-mail is not vulnerable as it seems. Yet the link in the e-mail seems to be the way to go.

```URL
https://0a6b000604d599ee84e5a42000b70041.web-security-academy.net/forgot-password?temp-forgot-password-token=e1pis85homejn450ibvsnm58233bw9pc
```

The request body when changing the password is as follows:

```Form-data
temp-forgot-password-token=e1pis85homejn450ibvsnm58233bw9pc&username=wiener&new-password-1=hej&new-password-2=hej
```

Trying to change the username to carlos should work. The payload is: `temp-forgot-password-token=e1pis85homejn450ibvsnm58233bw9pc&username=carlos&new-password-1=hej&new-password-2=hej`.

The request completes and returns 302. Trying to log in with the new password, works as intended. Note that the token must be valid. This solved the lab.