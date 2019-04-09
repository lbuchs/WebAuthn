[![Licensed under the MIT License](https://img.shields.io/badge/License-MIT-blue.svg)](https://github.com/lbuchs/WebAuthn/blob/master/LICENSE)
[![Requires PHP 5.6](https://img.shields.io/badge/PHP-%3E%3D%205.6-green.svg)](https://php.net)
[![Last Commit](https://img.shields.io/github/last-commit/lbuchs/WebAuthn.svg)](https://github.com/lbuchs/WebAuthn/commits/master)

# WebAuthn
*A simple PHP WebAuthn (FIDO2) server library*

Goal of this project is to provide a small, lightweight, understandable library to protect logins with security keys like Yubico or Solo or fingerprint on Android.

## Manual
See /_test for a simple usage of this library. Check [webauthn.lubu.ch](https://webauthn.lubu.ch) for a working example.

### Supported attestation statement formats
* android-key &#x2705;
* android-safetynet &#x2705;
* fido-u2f &#x2705;
* none &#x2705;
* packed &#x2705;
* tpm &#x274C;

This library supports only authenticators which are signed with a X.509 certificate (except for `none` format). ECDAA and self attestation is not supported.

## Workflow

             JAVASCRIPT            |          SERVER
    ------------------------------------------------------------
                             REGISTRATION


       window.fetch  ----------------->     getCreateArgs
                                                 |
    navigator.credentials.create   <-------------'
            |
            '------------------------->     processCreate
                                                 |
          alert ok or fail      <----------------'


    ------------------------------------------------------------
                          VALIDATION


       window.fetch ------------------>      getGetArgs
                                                 |
    navigator.credentials.get   <----------------'
            |
            '------------------------->      processGet
                                                 |
          alert ok or fail      <----------------'


## Resident Credential
A Client-side-resident Public Key Credential Source, or Resident Credential for short,
is a public key credential source whose credential private key is stored in the authenticator,
client or client device. Such client-side storage requires a resident credential capable authenticator.
This is only supported by FIDO2 hardware, not by older U2F hardware.
On the browser side, at the moment only Microsoft Edge 18 seems to be supporting it.

### How does it work?
With normal **server-side key** process, the user enters its username (and maybe password),
then the server replys with a list of all public key credential identifier, which had been registered by the user.
Then, the authenticator takes the first of the provided credential identifier, which has been issued by himself,
and responses with a signature which can be validated with the public key provided on registration.
With **client-side key** process, the user don't have to provide it's username or password, he can actually just press a 'login' button!
Then, the server don't send any identifier; rather, the authenticator is looking up in it's own memory,
if there is a key saved for this relying party. If yes, he's responding the same way like he's doing if you provide a
list of identifier, there is no difference in checking the registration.

### How can I use it with this library?
#### on registration
When calling `WebAuthn\WebAuthn->getCreateArgs`, set `$requireResidentKey` to true,
to notify the authenticator that he should save the registration in its memory.

#### on login
When calling `WebAuthn\WebAuthn->getGetArgs`, don't provide any `$credentialIds` (the authenticator will look up the ids in its own memory).

## Requirements
* PHP >= 5.6 with [OpenSSL](http://php.net/manual/en/book.openssl.php)
* Browser with [WebAuthn support](https://caniuse.com/webauthn) (Firefox 60+, Chrome 67+, Opera 54+, Edge 18+)

## Infos about WebAuthn
* [Wikipedia](https://en.wikipedia.org/wiki/WebAuthn)
* [W3C](https://www.w3.org/TR/webauthn/)
* [MDN](https://developer.mozilla.org/en-US/docs/Web/API/Web_Authentication_API)
* [dev.yubico](https://developers.yubico.com/FIDO2/)
* [FIDO Alliance](https://fidoalliance.org)

## FIDO2 Hardware
* [Yubico](https://www.yubico.com/products/yubikey-hardware/compare-yubikeys/)
* [Solo](https://solokeys.com) Open Source!
* [Feitan](https://www.ftsafe.com/Products/FIDO2)
* [eWBM](http://www.e-wbm.com/fido_usb.jsp)
* [Google Titan](https://cloud.google.com/titan-security-key)
* [Egis](https://www.egistec.com/u2f-solution/)
* [OneSpan](https://www.vasco.com/products/two-factor-authenticators/hardware/one-button/digipass-secureclick.html)
* [Hypersecu](https://hypersecu.com/products/hyperfido)