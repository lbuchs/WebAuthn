<?php

namespace WebAuthn;

/**
 * WebAuthn
 * @author Lukas Buchs
 */
class WebAuthn {
    // relying party
    private $_rpName;
    private $_rpId;
    private $_rpIdHash;
    private $_challenge;

    /**
     * Initialize a new WebAuthn
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

        if (\in_array('SHA256', \openssl_get_md_methods())) {
            throw new WebAuthnException('SHA256 not supported by this openssl installation.');
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
     * @return \stdClass
     */
    public function getCreateArgs($userId, $userName, $userDisplayName) {
        $args = new \stdClass();

        // relying party
        $args->rp = new \stdClass();
        $args->rp->name = $this->_rpName;
        $args->rp->id = $this->_rpId;

        // user
        $args->user = new \stdClass();
        $args->user->id = $this->_binAsBase64Str($userId);
        $args->user->name = $userName;
        $args->user->displayName = $userDisplayName;

        $args->pubKeyCredParams = new \stdClass();
        $args->pubKeyCredParams->type = 'public-key';
        $args->pubKeyCredParams->alg = -7; // SHA256

        $args->attestation = 'direct';
        $args->timeout = 20000; // 20s
        $args->challenge = $this->_binAsBase64Str($this->_createChallenge());

        return $args;
    }

    /**
     * generates the object for key validation
     * @param array $ids
     * @param bool $allowUsb
     * @param bool $allowNfc
     * @param bool $allowBle
     * @return \stdClass
     */
    public function getGetArgs($ids, $allowUsb=true, $allowNfc=true, $allowBle=true) {
        $args = new \stdClass();
        $args->publicKey = new \stdClass();
        $args->publicKey->timeout = 20000; // 20s
        $args->publicKey->challenge = $this->_binAsBase64Str($this->_createChallenge());
        $args->publicKey->allowCredentials = array();

        foreach ($ids as $id) {
            $tmp = new \stdClass();
            $tmp->id = $this->_binAsBase64Str($id);
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
     * process a create request and returns data to save for future logins
     * @param string $clientDataJSON binary from browser
     * @param string $attestationObject binary from browser
     * @param string $challenge binary used challange
     * @return \stdClass
     * @throws WebAuthnException
     */
    public function processCreate($clientDataJSON, $attestationObject, $challenge) {
        require_once 'Attestation/AttestationObject.php';
        $attestationObject = new Attestation\AttestationObject($attestationObject);
        $clientDataHash = \hash('sha256', $clientDataJSON, true);
        $clientData = \json_decode($clientDataJSON);

        if (!\is_object($clientData)) {
            throw new WebAuthnException('invalid client data');
        }

        if (!\property_exists($clientData, 'challenge') || $this->_base64url_decode($clientData->challenge) !== $challenge) {
            throw new WebAuthnException('invalid challenge');
        }

        if (!\property_exists($clientData, 'type') || $clientData->type !== 'webauthn.create') {
            throw new WebAuthnException('invalid type');
        }

        if (!$attestationObject->validateRpIdHash($this->_rpIdHash)) {
            throw new WebAuthnException('invalid rpId hash');
        }

        if (!$attestationObject->validateAttestation($clientDataHash)) {
            throw new WebAuthnException('invalid certificate signature');
        }

        if (!$attestationObject->getAuthenticatorData()->getUserPresent()) {
            throw new WebAuthnException('user present flag not set');
        }

        // prepare data to store for future logins
        $data = new \stdClass();
        $data->credentialId = $attestationObject->getAuthenticatorData()->getCredentialId();
        $data->credentialPublicKey = $attestationObject->getAuthenticatorData()->getPublicKeyPem();
        $data->certificate = $attestationObject->getCertificatePem();
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
     * @return boolean true if get is successful
     * @throws WebAuthnException
     */
    public function processGet($clientDataJSON, $authenticatorData, $signature, $credentialPublicKey, $challenge) {
        require_once 'Attestation/AttestationObject.php';
        $attestationObject = new Attestation\AttestationObject($authenticatorData);
        $clientDataHash = \hash('sha256', $clientDataJSON, true);
        $clientData = \json_decode($clientDataJSON);

        if (!\is_object($clientData)) {
            throw new WebAuthnException('invalid client data');
        }
        
        if (!$attestationObject->getAuthenticatorData()->getUserPresent()) {
            throw new WebAuthnException('user present flag not set');
        }

        if (!\property_exists($clientData, 'challenge') || $this->_base64url_decode($clientData->challenge) !== $challenge) {
            throw new WebAuthnException('invalid challenge');
        }

        if (!\property_exists($clientData, 'type') || $clientData->type !== 'webauthn.get') {
            throw new WebAuthnException('invalid type');
        }

        if (!$attestationObject->validateRpIdHash($this->_rpIdHash)) {
            throw new WebAuthnException('invalid rpId hash');
        }

        $dataToVerify = '';
        $dataToVerify .= $authenticatorData;
        $dataToVerify .= $clientDataHash;

        $publicKey = \openssl_pkey_get_public($credentialPublicKey);
        if ($publicKey === false) {
            throw new WebAuthnException('public key invalid');
        }

        // signature is okay or not
        if (\openssl_verify($dataToVerify, $signature, $publicKey, OPENSSL_ALGO_SHA256) !== 1) {
            throw new WebAuthnException('invalid signature');
        }

        return true;
    }

    // -----------------------------------------------
    // PRIVATE
    // -----------------------------------------------

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

    /**
     * returns a string formated by RFC 1342
     * @param string $binary
     * @param string $charset
     * @return string
     */
    private function _binAsBase64Str($binary, $charset='') {
        // RFC 1342
        return '?' . $charset . '?B?' . \base64_encode($binary) . '?=';
    }

    /**
     * decode base64 url
     * @param string $data
     * @return string
     */
    private function _base64url_decode($data) {
      return \base64_decode(\strtr($data, '-_', '+/') . \str_repeat('=', 3 - (3 + \strlen($data)) % 4));
    }
}
