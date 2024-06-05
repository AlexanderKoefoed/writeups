# Reverse engineering exercises from Hackerspace course 2024

This writeup covers the exercises (a part from the "ReverseMe" challenge) from Hackerspace 2024.

## GhidraCrack.exe

This exercise aims to gain familiartiy with Flare VM, Ghidra and reversing Windows `.exe` files.

## IDA-Crack.exe

This exercise aims to gain familiartiy with Flare VM, IDA and reversing Windows `.exe` files.

## SafeVault.jar

This exercise aims to gain familiarity with the Java decompiler.

Decompiling the SafeVault.jar file reveals a single class called Vault. This class consists of 3 methods:

- `main`
- `print`
- `rot13`

The print function is implemented to make bruteforcing annoying, as it sleeps the thread after each printed char.

The main class quickly reveals a byte array called `toCompare`, which is being used in an if statement. If the statement returns true, we win by gaining access to the vault. The check is:

```Java
if ((new String(Base64.getDecoder().decode(rot13(input)))).equals(new String(Base64.getDecoder().decode(rot13(new String(toCompare)))))) {
        print("The Vault system has started successfully!");
      } else {
        print("The Vault system has not started successfully!");
      } 
```

Thus we have to provide an input which will equals the byte array as a string, mutated with the `rot13` function and then Base64 encoded. Should be pretty straight forward.
First lets look at the `rot13` function. It is a standard shift cipher which replaces the character with the character 13 places after the original in the latin alphabet:

```Java
  public static String rot13(String input) {
    StringBuilder sb = new StringBuilder();
    for (int i = 0; i < input.length(); i++) {
      char c = input.charAt(i);
      if (c >= 'a' && c <= 'm') {
        c = (char)(c + 13);
      } else if (c >= 'A' && c <= 'M') {
        c = (char)(c + 13);
      } else if (c >= 'n' && c <= 'z') {
        c = (char)(c - 13);
      } else if (c >= 'N' && c <= 'Z') {
        c = (char)(c - 13);
      } 
      sb.append(c);
    } 
    return sb.toString();
  }
```

As seen in the code, it checks for upper and lowercase letters and depending on the location of the original char `c` it adds or subtracts 13 from the char.

The toCompare byte array is defined as:

```Java
    byte[] toCompare = { 
        101, 109, 100, 122, 101, 51, 99, 48, 97, 87, 
        53, 102, 99, 122, 66, 108, 88, 51, 107, 120, 
        99, 122, 78, 57 };
```

Using cyberchef, the bytes can be decoded, applying both base64 decoding and rot13 will produce the flag: `mtf{j4va_f0r_l1f3}`. This confirms that we have to reverse the input to successfully start the program. This is quite easily done with cyberchef, as we simply take the bytes from the byte array and encode them with the "Decimal" function, producing the base64 encoded string: `emdze3c0aW5fczBlX3kxczN9`. starting the SafeVault.jar with the arguments: `java -jar SafeVault.jar --enable-vault emdze3c0aW5fczBlX3kxczN9` will producue the output `Welcome to Vault Systems version 0.1! The Vault system has started successfully!` and we win! 

**NOTE**: The `--enable-vault` argument is needed as seen in the main function:

```Java
    print("Welcome to Vault Systems version 0.1!");
    if (args.length < 2) {
      print("It seems that Vault Systems cannot function properly.\nMore information can be found in the manual, in chapter 82, section 17.");
    } else if (args[0].equals("--enable-vault")) {
              String input = args[1];
              ...
```

## RepeatReverseRepeat

Looks like a powershell script. Seemingly it contains a very large base64 string. Decoding this string reveals another large base64 string. This seems like it will keep on being base64 encoded. To solve this challenge, a python script was implemented to unpack the recusively encoded strings:

```Python
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
```

The `RepeatReverseRepeat.ps1` file has a defined string in the start of each encoded string. It looks like: `ieX([systEm.tExt.EnCODIng]::Utf8.gEtSTriNg([syStEm.CONvErt]::FROMbasE64sTrIng("`. This is used to split the file on Quotes to obtain the base64 string. Then it is decoded and parsed to be decoded again until the string is not present in the entire file anymore. This reveals the flag: `mtf{4ut0m4t10n_1s_k3y}`.

## SafeReverse

Probably linux with Java decompiler

## WhatsTheARG

Windows environment with IDA
