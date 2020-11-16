[![Licensed under the MIT License](https://img.shields.io/badge/License-MIT-blue.svg)](https://github.com/lbuchs/WebAuthn/blob/master/LICENSE)
[![Requires PHP 7.1.0](https://img.shields.io/badge/PHP-7.1.0-green.svg)](https://php.net)
[![Last Commit](https://img.shields.io/github/last-commit/lbuchs/WebAuthn.svg)](https://github.com/lbuchs/WebAuthn/commits/master)

# WebAuthn
*A simple PHP WebAuthn (FIDO2) server library*

Goal of this project is to provide a small, lightweight, understandable library to protect logins with security keys like Yubico or Solo, fingerprint on Android or Windows Hello.

## Manual
See /_test for a simple usage of this library. Check [webauthn.lubu.ch](https://webauthn.lubu.ch) for a working example.

### Supported attestation statement formats
* android-key &#x2705;
* android-safetynet &#x2705;
* apple &#x2705;
* fido-u2f &#x2705;
* none &#x2705;
* packed &#x2705;
* tpm &#x2705;

This library supports authenticators which are signed with a X.509 certificate or which are self attested. ECDAA is not supported.

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

### How does it work?
With normal **server-side key** process, the user enters its username (and maybe password),
then the server replys with a list of all public key credential identifier, which had been registered by the user.
Then, the authenticator takes the first of the provided credential identifier, which has been issued by himself,
and responses with a signature which can be validated with the public key provided on registration.
With **client-side key** process, the user don't have to provide an username or password.
The server don't send any identifier; rather, the authenticator is looking up in it's own memory,
if there is a key saved for this relying party. If yes, he's responding the same way like he's doing if you provide a
list of identifier, there is no difference in checking the registration.
Resident Credential is supported by Windows 10 (Firefox, Chromium). Browser on old OS like Windows 7
do a fallback to FIDO U2F, which doesn't support resident credential.

### How can I use it with this library?
#### on registration
When calling `WebAuthn\WebAuthn->getCreateArgs`, set `$requireResidentKey` to true,
to notify the authenticator that he should save the registration in its memory.

#### on login
When calling `WebAuthn\WebAuthn->getGetArgs`, don't provide any `$credentialIds` (the authenticator will look up the ids in its own memory).

## Requirements
* PHP >= 7.1.0 with [OpenSSL](http://php.net/manual/en/book.openssl.php)
* Browser with [WebAuthn support](https://caniuse.com/webauthn) (Firefox 60+, Chrome 67+, Opera 54+, Edge 18+)

## Infos about WebAuthn
* [Wikipedia](https://en.wikipedia.org/wiki/WebAuthn)
* [W3C](https://www.w3.org/TR/webauthn/)
* [MDN](https://developer.mozilla.org/en-US/docs/Web/API/Web_Authentication_API)
* [dev.yubico](https://developers.yubico.com/FIDO2/)
* [FIDO Alliance](https://fidoalliance.org)

## FIDO2 Hardware
* [Yubico](https://www.yubico.com)
* [Solo](https://solokeys.com) Open Source!
* [Nitrokey](https://www.nitrokey.com/)
* [Feitan](https://fido.ftsafe.com/)
* [TrustKey](https://www.trustkeysolutions.com)
* [Google Titan](https://cloud.google.com/titan-security-key)
* [Egis](https://www.egistec.com/u2f-solution/)
* [OneSpan](https://www.vasco.com/products/two-factor-authenticators/hardware/one-button/digipass-secureclick.html)
* [Hypersecu](https://hypersecu.com/tmp/products/hyperfido)
* [Kensington VeriMark™](https://www.kensington.com/)