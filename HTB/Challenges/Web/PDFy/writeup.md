# PDFy

**Source**: No.

Challenge description: Welcome to PDFy, the exciting challenge where you turn your favorite web pages into portable PDF documents! It's your chance to capture, share, and preserve the best of the internet with precision and creativity. Join us and transform the way we save and cherish web content! NOTE: Leak /etc/passwd to get the flag!

## Challenge Solution

We are presented with a webpage which allows us to generate PDFs based on a website. Lets try to use the functionality. Using `https://google.com` as suggested by the input field, we get a screenshot of the document embedded in the page. This screenshot is a pdf document which is cached under a random file name in the static directory:

```JSON
{
  "domain": "google.com",
  "filename": "0e7c8f1c2d59843bdb00fbdb957e.pdf",
  "level": "success",
  "message": "Successfully cached google.com"
}
```

File location: `http://94.237.49.166:35153/static/pdfs/0e7c8f1c2d59843bdb00fbdb957e.pdf`.

The goal is probably to make a pdf (screenshot) of the `/etc/passwd` file and get it to return this. This might be done by making the request for the file return the `passwd` file, this would be possible if we can make get path traversal in the url. If that does not work, we might be able to cache the file in the static folder.

```JSON
"There was an error: Error generating PDF: Command '['wkhtmltopdf', '--margin-top', '0', '--margin-right', '0', '--margin-bottom', '0', '--margin-left', '0', 'https://a', 'application/static/pdfs/41477c78aade9fd17fafbdf65329.pdf']' returned non-zero exit status 1."
```

Solution:
Iframe redirected with a location header (HTTP 301)

Exploit:
`https://exploit-notes.hdks.org/exploit/web/security-risk/wkhtmltopdf-ssrf/`