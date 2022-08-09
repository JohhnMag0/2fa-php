# 2fa PHP

A simple TOTP and HOTP library for php. With this library you can generate tokens, URI's and QRcodes.

# Usage
____
## Token

If you just want to generate a simple token with 6 digits, count 0(for HOTP) or 30 seconds(for TOTP) and sha1 as the algorithm, just use as follow:

```
<?php
include('2fa.php');

// Time based token
$x = new TOTP();

// Count based token
$y = new HOTP();

echo $x->OTP('hello');
echo $y->OTP('hello');
```

If you want to modify the token that will be generate you can adjust some variables:

```
$x = new TOTP();

//Change the count/time
$time = 60;

//Number of digits. The max is 9 digits
$digits = 9;

//Algorithm that will be used. Only the sha1, sha256 and sha512 are supported
$algo = 'sha512';

//Verify Time. Only used on TOTP and beware it can be slower than just use the time in the machine
$ntp = true;

echo $x->OTP('hello', $time, $digits, $algo, $ntp);
```

Generating a URI:

```
$x = new TOTP();

//Secret(required)
$secret = 'hello';

//User(required)
$user = 'Someone';

//Issuer(required)
$issuer = 'Somecompany';

//Period/count(optional). If not set the standard is 0 for count and 30 seconds for time
$window = 60;

//Algorithm(optional). The standard is sha1
$algo = 'sha256';

//Digits(optional). The standard is 6
$digits = 9;
```

Generating the QRCode:
```
$x = new TOTP();

//Before you generate the QRCode you will need to generate the URI
$uri = $x->URI('hello', 'user', 'issuer');

//Generates the QRCode to use in HTML
$qr = $x->QRCodeHTML($uri);

echo $qr;

//Save the QRCode as a gif image 
$path = '/tmp/qrcode.gif';
$x->QRCodeImage($path);
``` 
___
# Documentation
If you want to get an overview of how this library works under the hood, I have an article that ~~tries to~~ explain some of the technology being used. You can see this article on here: https://johhnmag0.github.io/post/2022/08/08/2fa-authentication-php/

OBS.: It's very important to say that the QRCode library was not made by me. The one that is being used is part of this project: https://github.com/kazuhikoarase/qrcode-generator. So kudos to Kazuhikoarase for making this beautiful library.
