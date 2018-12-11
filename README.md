[![Licensed under the MIT License](https://img.shields.io/badge/License-MIT-blue.svg)](https://github.com/lbuchs/WebAuthn/blob/master/LICENSE)
[![Requires PHP 5.6](https://img.shields.io/badge/PHP-%3E%3D%205.6-green.svg)](https://php.net)
[![Last Commit](https://img.shields.io/github/last-commit/lbuchs/WebAuthn.svg)](https://github.com/lbuchs/WebAuthn/commits/master)

# WebAuthn
A simple PHP WebAuthn (FIDO2) server library

## Manual
See /_test for a simple usage of this library. Check [webauthn.lubu.ch](https://webauthn.lubu.ch) for a working example. This Library cannot handle _Client-side-resident Public Key Credential Source_ (yet), so it's not suited for passwordless experience, but for second-factor authentication (2FA).

## Requirements
* PHP >= 5.6 with [OpenSSL](http://de.php.net/manual/en/book.openssl.php)
* Browser with [WebAuthn support](https://caniuse.com/webauthn) (Firefox 60+, Chrome 67+, Opera 54+, Edge 18+)

## Infos about WebAuthn
* [Wikipedia](https://en.wikipedia.org/wiki/WebAuthn)
* [W3C](https://www.w3.org/TR/webauthn/)
* [MDN](https://developer.mozilla.org/en-US/docs/Web/API/Web_Authentication_API)
* [dev.yubico](https://developers.yubico.com/FIDO2/)
* [FIDO Alliance](https://fidoalliance.org)

## FIDO2 Hardware
* [Yubico](https://www.yubico.com/products/yubikey-hardware/compare-yubikeys/)
* [Solo](https://solokeys.com) Open Source! 😍
* [Feitan](https://www.ftsafe.com/Products/FIDO2)
* [eWBM](http://www.e-wbm.com/fido_usb.jsp)
* [Google Titan](https://cloud.google.com/titan-security-key)
* [Egis](https://www.egistec.com/u2f-solution/)
* [OneSpan](https://www.vasco.com/products/two-factor-authenticators/hardware/one-button/digipass-secureclick.html)
