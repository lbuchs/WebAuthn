[![Licensed under the MIT License](https://img.shields.io/badge/License-MIT-blue.svg)](https://github.com/lbuchs/WebAuthn/blob/master/LICENSE)
[![Requires PHP 5.6](https://img.shields.io/badge/PHP-%3E%3D%205.6-green.svg)](https://php.net)
[![Last Commit](https://img.shields.io/github/last-commit/lbuchs/WebAuthn.svg)](https://github.com/lbuchs/WebAuthn/commits/master)
[![Its beta!](https://img.shields.io/badge/release-beta-red.svg)](https://github.com/lbuchs/WebAuthn/)

# WebAuthn
A simple PHP WebAuthn (FIDO2) server library

## Manual
See /_test for a very simple usage of this library. Check [webauthn.lubu.ch](https://webauthn.lubu.ch) for a working example.

Please remind that you'll need a way to transport binary data from PHP to JavaScript.
This is not part of this library. Look at the /_test scripts for a simple implementation with base64.

## Todo
* detect length of attestedCredentialData if extension data is present. [problem description](https://groups.google.com/a/fidoalliance.org/forum/#!topic/fido-dev/lZ24VfPcDic)

## Infos about WebAuthn
* [Wikipedia](https://en.wikipedia.org/wiki/WebAuthn)
* [W3C](https://www.w3.org/TR/webauthn/)
* [MDN](https://developer.mozilla.org/en-US/docs/Web/API/Web_Authentication_API)
* [dev.yubico](https://developers.yubico.com/FIDO2/)
* [FIDO Alliance](https://fidoalliance.org)

## Requirements
* PHP >= 5.6 with [OpenSSL](http://de.php.net/manual/en/book.openssl.php)
* Browser with [WebAuthn support](https://caniuse.com/webauthn) (Firefox 60+, Chrome 67+, Opera 54+, Edge 18+)

## Dependencies
* copy of CBOR library from [2tvenom/CBOREncode](https://github.com/2tvenom/CBOREncode "2tvenoms CBOREncoder") is included in this project (subject to change)