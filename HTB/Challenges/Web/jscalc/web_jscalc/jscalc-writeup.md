# Challenge: jscalc

**Lab Description**: In the mysterious depths of the digital sea, a specialized JavaScript calculator has been crafted by tech-savvy squids. With multiple arms and complex problem-solving skills, these cephalopod engineers use it for everything from inkjet trajectory calculations to deep-sea math. Attempt to outsmart it at your own risk! 🦑

## Lab Solution

The challenge comes with source files. Particularly the `calculatorHelper.js` looks promising with a Javascript eval funtion taking an argument. The website also suggest this file indirectly through the headline tag `A super secure Javascript calculator with the help of eval() 🤮`.

The JS eval function takes javascript code and executes it directly on the server. In this instance, the request body to `/api/calculate` is parsed directly to the eval() function. As this is a nodejs backend an attacker would be able to input any nodejs functions and get RCE. To read any file on the server the `fs` would be ideal. Using `Object.keys(require('fs'))` shows which functions are able to be executed on this object. Using that to craft the payload: `require('fs').readFileSync('/flag.txt').toString();`.

Supply this to the instance and we will get flag!
