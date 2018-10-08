[![Licensed under the MIT License](https://img.shields.io/badge/License-MIT-blue.svg)](https://github.com/lbuchs/WebAuthn/blob/master/LICENSE)
[![Requires PHP 5.4.8](https://img.shields.io/badge/PHP-%3E%3D%205.4.8-green.svg)](https://php.net)
[![Last Commit](https://img.shields.io/github/last-commit/lbuchs/WebAuthn.svg)](https://github.com/lbuchs/WebAuthn/commits/master)
[![Its beta!](https://img.shields.io/badge/release-beta-red.svg)](https://github.com/lbuchs/WebAuthn/)

# WebAuthn
A simple PHP WebAuthn (FIDO2) server library

## state
Working, but further security checks necessary. Do not use in productive systems without accurate testing and security analysis.

## todo's
* check root certificates
* security analysis

## infos about WebAuthn
* [Wikipedia](https://en.wikipedia.org/wiki/WebAuthn)
* [W3C](https://www.w3.org/TR/webauthn/)
* [MDN](https://developer.mozilla.org/en-US/docs/Web/API/Web_Authentication_API)
* [dev.yubico](https://developers.yubico.com/FIDO2/)

## dependencies
* PHP >= 5.4.8 with [OpenSSL](http://de.php.net/manual/en/book.openssl.php)
* modified copy of CBOR library from [2tvenom/CBOREncode](https://github.com/2tvenom/CBOREncode "2tvenoms CBOREncoder") is included in this project (subject to change)