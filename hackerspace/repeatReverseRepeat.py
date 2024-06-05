import base64


def read(data):
    encoded = data.split(b'"')[1]
    res = base64.b64decode(encoded)
    return res

with open("./RepeatReverseRepeat.ps1", "rb") as file:
    data = file.read()
    while True:
        data = read(data)
        print(data[:20])
        if not b"frombase64string" in data.lower():
            print(data)
            break
