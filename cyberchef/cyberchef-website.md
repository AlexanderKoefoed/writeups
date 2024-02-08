# Cyberchef

Randomly inspected the Cyberchef website and saw a large console log of Hex characters. Decoded it and found the following message:

*Congratulations, you have completed CyberChef challenge #1! This challenge explored hexadecimal encoding. To learn more, visit wikipedia.org/wiki/Hexadecimal. The code for this challenge is private-string (keep this private). The next challenge can be found at https://pastebin.com/--string--.*

For the next challenge pastebin.com is visited.

## Challenge 2

The next challenge was decoding a long string. Because it had two *==* appended at the end of the string, and consisted only of ordinary characters, it was suspected to be Base64 encoded. Which was correct. The next challenge is another pastebin.

## Challenge 3

This challenge seemed to be Hex characters as well, but included an extra step. It used URL Percent encoding for the spaces in the string. Which means it has to be decoded in two steps with *From Hex* and then *URL Decode*.

## Challenge 4

This challenge was also Hex encoded, and provided a hint `Hint: detect file type`. Using this parameter in Cyberchef provided the file type as Gzip. Using the knowledge of the Compression scheme, some research provided that gzip uses LZ77 compression. This prompted to try the LZ4 decompress found on cyberchef, but sadly did not yield any result. Further investigating the cyberchef repotoire showed a function called *Gunzip*. *Gunzip* Decompresses data which has been compressed using the deflate algorithm.

## Challenge 5

This challenge is the first to pose a challenge, no hints and a weird output when decoding *from hex*. Turns out it needed something called "Quoted-printable" and then decompression from Bzip2 as the Detect file type suggested.

## Challenge 6

This one needed to be base64 decoded, then using the Gunzip a string appeared. It had the same form as the previous challenges:

*Pbatenghyngvbaf, lbh unir pbzcyrgrq PlorePurs punyyratr #6! Guvf punyyratr rkcyberq EBG13 rapbqvat. Gb yrnea zber, ivfvg jvxvcrqvn.bet/jvxv/EBG13. Gur pbqr sbe guvf punyyratr vf 4s946qo0-134r-4666-9424-405053o0888s. Gur arkg punyyratr pna or sbhaq ng uuggcf://cnfgrova.pbz/O7z2qHXY.*

It is seen that some instances of text are on the same form, for example *Gur* is mentioned twice, leading to the realization that this could be a shift cipher, mayber caesar? Turned out to be ROT13.

## Challenge 7

