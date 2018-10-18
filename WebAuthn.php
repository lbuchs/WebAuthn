<?php

namespace WebAuthn;

/**
 * WebAuthn
 * @author Lukas Buchs
 * @license https://github.com/lbuchs/WebAuthn/blob/master/LICENSE MIT
 */
class WebAuthn {
    // relying party
    private $_rpName;
    private $_rpId;
    private $_rpIdHash;
    private $_challenge;
    private $_signatureCounter;
    private $_caFiles;

    /**
     * Initialize a new WebAuthn server
     * @param string $rpName the relying party name
     * @param string $rpId the relying party ID = the domain name
     * @throws WebAuthnException
     */
    public function __construct($rpName, $rpId) {
        require_once 'WebAuthnException.php';
        $this->_rpName = $rpName;
        $this->_rpId = $rpId;
        $this->_rpIdHash = \hash('sha256', $rpId, true);

        if (!\function_exists('\openssl_open')) {
            throw new WebAuthnException('OpenSSL-Module not installed');;
        }

        if (!\in_array('SHA256', \openssl_get_md_methods())) {
            throw new WebAuthnException('SHA256 not supported by this openssl installation.');
        }
    }

    /**
     * add a root certificate to verify new registrations
     * @param string $path file path of / directory with root certificates
     */
    public function addRootCertificates($path) {
        if (!\is_array($this->_caFiles)) {
            $this->_caFiles = array();
        }
        $path = \rtrim(\trim($path), '\\/');
        if (\is_dir($path)) {
            foreach (\scandir($path) as $ca) {
                if (\is_file($path . '/' . $ca)) {
                    $this->addRootCertificates($path . '/' . $ca);
                }
            }
        } else if (\is_file($path) && !\in_array(\realpath($path), $this->_caFiles)) {
            $this->_caFiles[] = \realpath($path);
        }
    }

    /**
     * Returns the generated challenge to save for later validation
     * @return string
     */
    public function getChallenge() {
        return $this->_challenge;
    }

    /**
     * generates the object for a key registration
     * @param string $userId
     * @param string $userName
     * @param string $userDisplayName
     * @param int $timeout timeout in seconds
     * @return \stdClass
     */
    public function getCreateArgs($userId, $userName, $userDisplayName, $timeout=20) {
        $args = new \stdClass();
        $args->publicKey = new \stdClass();

        // relying party
        $args->publicKey->rp = new \stdClass();
        $args->publicKey->rp->name = $this->_rpName;
        $args->publicKey->rp->id = $this->_rpId;

        // user
        $args->publicKey->user = new \stdClass();
        $args->publicKey->user->id = $userId; // binary
        $args->publicKey->user->name = $userName;
        $args->publicKey->user->displayName = $userDisplayName;

        $args->publicKey->pubKeyCredParams = array();
        $tmp = new \stdClass();
        $tmp->type = 'public-key';
        $tmp->alg = -7; // SHA256
        $args->publicKey->pubKeyCredParams[] = $tmp;

        $args->publicKey->attestation = 'direct';
        $args->publicKey->extensions = new \stdClass();
        $args->publicKey->extensions->exts = true;
        $args->publicKey->timeout = $timeout * 1000; // microseconds
        $args->publicKey->challenge = $this->_createChallenge(); // binary

        return $args;
    }

    /**
     * generates the object for key validation
     * @param array $credentialIds binary
     * @param int $timeout timeout in seconds
     * @param bool $allowUsb
     * @param bool $allowNfc
     * @param bool $allowBle
     * @return \stdClass
     */
    public function getGetArgs($credentialIds, $timeout=20, $allowUsb=true, $allowNfc=true, $allowBle=true) {
        $args = new \stdClass();
        $args->publicKey = new \stdClass();
        $args->publicKey->timeout = $timeout * 1000; // microseconds
        $args->publicKey->challenge = $this->_createChallenge();  // binary
        $args->publicKey->allowCredentials = array();

        foreach ($credentialIds as $id) {
            $tmp = new \stdClass();
            $tmp->id = $id;  // binary
            $tmp->transports = array();

            if ($allowUsb) {
                $tmp->transports[] = 'usb';
            }
            if ($allowNfc) {
                $tmp->transports[] = 'nfc';
            }
            if ($allowBle) {
                $tmp->transports[] = 'ble';
            }

            $tmp->type = 'public-key';
            $args->publicKey->allowCredentials[] = $tmp;
            unset ($tmp);
        }

        return $args;
    }

    /**
     * returns the new signature counter value.
     * returns false if there is no counter
     * @return int|bool
     */
    public function getSignatureCounter() {
        return is_int($this->_signatureCounter) ? $this->_signatureCounter : null;
    }

    /**
     * process a create request and returns data to save for future logins
     * @param string $clientDataJSON binary from browser
     * @param string $attestationObject binary from browser
     * @param string $challenge binary used challange
     * @param bool $requireUserVerification true, if the device must verify user (e.g. by biometric data or pin)
     * @param bool $requireUserPresent true, if the device must check user presence (e.g. by pressing a button)
     * @return \stdClass
     * @throws WebAuthnException
     */
    public function processCreate($clientDataJSON, $attestationObject, $challenge, $requireUserVerification=false, $requireUserPresent=true) {
        require_once 'Attestation/AttestationObject.php';
        $attestationObject = new Attestation\AttestationObject($attestationObject);
        $clientDataHash = \hash('sha256', $clientDataJSON, true);
        $clientData = \json_decode($clientDataJSON);

        // security: https://www.w3.org/TR/webauthn/#registering-a-new-credential

        // 2. Let C, the client data claimed as collected during the credential creation,
        //    be the result of running an implementation-specific JSON parser on JSONtext.
        if (!\is_object($clientData)) {
            throw new WebAuthnException('invalid client data');
        }

        // 3. Verify that the value of C.type is webauthn.create.
        if (!\property_exists($clientData, 'type') || $clientData->type !== 'webauthn.create') {
            throw new WebAuthnException('invalid type');
        }

        // 4. Verify that the value of C.challenge matches the challenge that was sent to the authenticator in the create() call.
        if (!\property_exists($clientData, 'challenge') || $this->_base64url_decode($clientData->challenge) !== $challenge) {
            throw new WebAuthnException('invalid challenge');
        }

        // 5. Verify that the value of C.origin matches the Relying Party's origin.
        if (!\property_exists($clientData, 'origin') || !$this->_checkOrigin($clientData->origin)) {
            throw new WebAuthnException('invalid origin');
        }

        // 9. Verify that the RP ID hash in authData is indeed the SHA-256 hash of the RP ID expected by the RP.
        if (!$attestationObject->validateRpIdHash($this->_rpIdHash)) {
            throw new WebAuthnException('invalid rpId hash');
        }

        // 14. Verify that attStmt is a correct attestation statement, conveying a valid attestation signature
        if (!$attestationObject->validateAttestation($clientDataHash)) {
            throw new WebAuthnException('invalid certificate signature');
        }

        // 15. If validation is successful, obtain a list of acceptable trust anchors
        if (is_array($this->_caFiles) && !$attestationObject->validateRootCertificate($this->_caFiles)) {
            throw new WebAuthnException('invalid root certificate');
        }

        // 10. Verify that the User Present bit of the flags in authData is set.
        if ($requireUserPresent && !$attestationObject->getAuthenticatorData()->getUserPresent()) {
            throw new WebAuthnException('user not present during authentication');
        }

        // 11. If user verification is required for this registration, verify that the User Verified bit of the flags in authData is set.
        if ($requireUserVerification && !$attestationObject->getAuthenticatorData()->getUserVerified()) {
            throw new WebAuthnException('user not verificated during authentication');
        }

        $signCount = $attestationObject->getAuthenticatorData()->getSignCount();
        if ($signCount > 0) {
            $this->_signatureCounter = $signCount;
        }

        // prepare data to store for future logins
        $data = new \stdClass();
        $data->credentialId = $attestationObject->getAuthenticatorData()->getCredentialId();
        $data->credentialPublicKey = $attestationObject->getAuthenticatorData()->getPublicKeyPem();
        $data->certificate = $attestationObject->getCertificatePem();
        $data->signatureCounter = $this->_signatureCounter;
        $data->AAGUID = $attestationObject->getAuthenticatorData()->getAAGUID();
        return $data;
    }


    /**
     * process a get request
     * @param string $clientDataJSON binary from browser
     * @param string $authenticatorData binary from browser
     * @param string $signature binary from browser
     * @param string $credentialPublicKey binary from used credentialId
     * @param string $challenge  binary from used challange
     * @param int $prevSignatureCnt signature count value of the last login
     * @param bool $requireUserVerification true, if the device must verify user (e.g. by biometric data or pin)
     * @param bool $requireUserPresent true, if the device must check user presence (e.g. by pressing a button)
     * @return boolean true if get is successful
     * @throws WebAuthnException
     */
    public function processGet($clientDataJSON, $authenticatorData, $signature, $credentialPublicKey, $challenge, $prevSignatureCnt=null, $requireUserVerification=false, $requireUserPresent=true) {
        require_once 'Attestation/AuthenticatorData.php';
        $authenticatorObj = new Attestation\AuthenticatorData($authenticatorData);
        $clientDataHash = \hash('sha256', $clientDataJSON, true);
        $clientData = \json_decode($clientDataJSON);

        // https://www.w3.org/TR/webauthn/#verifying-assertion

        // 1. If the allowCredentials option was given when this authentication ceremony was initiated,
        //    verify that credential.id identifies one of the public key credentials that were listed in allowCredentials.
        //    -> TO BE VERIFIED BY IMPLEMENTATION

        // 2. If credential.response.userHandle is present, verify that the user identified
        //    by this value is the owner of the public key credential identified by credential.id.
        //    -> TO BE VERIFIED BY IMPLEMENTATION

        // 3. Using credential’s id attribute (or the corresponding rawId, if base64url encoding is
        //    inappropriate for your use case), look up the corresponding credential public key.
        //    -> TO BE LOOKED UP BY IMPLEMENTATION

        // 5. Let JSONtext be the result of running UTF-8 decode on the value of cData.
        if (!\is_object($clientData)) {
            throw new WebAuthnException('invalid client data');
        }

        // 7. Verify that the value of C.type is the string webauthn.get.
        if (!\property_exists($clientData, 'type') || $clientData->type !== 'webauthn.get') {
            throw new WebAuthnException('invalid type');
        }

        // 8. Verify that the value of C.challenge matches the challenge that was sent to the
        //    authenticator in the PublicKeyCredentialRequestOptions passed to the get() call.
        if (!\property_exists($clientData, 'challenge') || $this->_base64url_decode($clientData->challenge) !== $challenge) {
            throw new WebAuthnException('invalid challenge');
        }

        // 9. Verify that the value of C.origin matches the Relying Party's origin.
        if (!\property_exists($clientData, 'origin') || !$this->_checkOrigin($clientData->origin)) {
            throw new WebAuthnException('invalid origin');
        }
        
        // 11. Verify that the rpIdHash in authData is the SHA-256 hash of the RP ID expected by the Relying Party.
        if ($authenticatorObj->getRpIdHash() !== $this->_rpIdHash) {
            throw new WebAuthnException('invalid rpId hash');
        }

        // 12. Verify that the User Present bit of the flags in authData is set
        if ($requireUserPresent && !$authenticatorObj->getUserPresent()) {
            throw new WebAuthnException('user not present during authentication');
        }

        // 13. If user verification is required for this assertion, verify that the User Verified bit of the flags in authData is set.
        if ($requireUserVerification && !$authenticatorObj->getUserVerified()) {
            throw new WebAuthnException('user not verificated during authentication');
        }

        // 14. Verify the values of the client extension outputs
        //     (extensions not implemented)

        // 16. Using the credential public key looked up in step 3, verify that sig is a valid signature
        //     over the binary concatenation of authData and hash.
        $dataToVerify = '';
        $dataToVerify .= $authenticatorData;
        $dataToVerify .= $clientDataHash;

        $publicKey = \openssl_pkey_get_public($credentialPublicKey);
        if ($publicKey === false) {
            throw new WebAuthnException('public key invalid');
        }

        if (\openssl_verify($dataToVerify, $signature, $publicKey, OPENSSL_ALGO_SHA256) !== 1) {
            throw new WebAuthnException('invalid signature');
        }

        // 17. If the signature counter value authData.signCount is nonzero,
        //     if less than or equal to the signature counter value stored,
        //     is a signal that the authenticator may be cloned
        $signatureCounter = $authenticatorObj->getSignCount();
        if ($signatureCounter > 0) {
            $this->_signatureCounter = $signatureCounter;
            if ($prevSignatureCnt !== null && $prevSignatureCnt >= $signatureCounter) {
                throw new WebAuthnException('signature counter not valid');
            }
        }

        return true;
    }

    // -----------------------------------------------
    // PRIVATE
    // -----------------------------------------------

    /**
     * decode base64 url
     * @param string $data
     * @return string
     */
    private function _base64url_decode($data) {
        return \base64_decode(\strtr($data, '-_', '+/') . \str_repeat('=', 3 - (3 + \strlen($data)) % 4));
    }

    /**
     * checks if the origin matchs the RP ID
     * @param string $origin
     * @return boolean
     * @throws WebAuthnException
     */
    private function _checkOrigin($origin) {
        // https://www.w3.org/TR/webauthn/#rp-id
        
        // The origin's scheme must be https
        if ($this->_rpId !== 'localhost' && \parse_url($origin, PHP_URL_SCHEME) !== 'https') {
            throw new WebAuthnException('origin not valid: scheme must be https.');
        }

        // extract host from origin
        $host = \parse_url($origin, PHP_URL_HOST);
        $host = \trim($host, '.');

        // The RP ID must be equal to the origin's effective domain, or a registrable domain suffix of the origin's effective domain.
        return \preg_match('/' . \preg_quote($this->_rpId) . '$/i', $host) === 1;
    }

    /**
     * generates a new challange
     * @param int $length
     * @return string
     * @throws WebAuthnException
     */
    private function _createChallenge($length = 32) {
        if (!$this->_challenge) {
            $crypto_strong = false;
            $this->_challenge = \openssl_random_pseudo_bytes($length, $crypto_strong);
            if (!$crypto_strong) {
                throw new WebAuthnException('cannot create crypto-strong random bytes.');
            }
        }
        return $this->_challenge;
    }
}
