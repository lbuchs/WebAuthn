<?php

namespace WebAuthn\Attestation;
use \WebAuthn\WebAuthnException;
use \WebAuthn\CBOR\CborDecoder;
use WebAuthn\Binary\ByteBuffer;

/**
 * @author Lukas Buchs
 * @license https://github.com/lbuchs/WebAuthn/blob/master/LICENSE MIT
 */
class AttestationObject {
    private $_signature;
    private $_x5c;
    private $_authenticatorData;
    private $_attestationFormat;

    private static $_SHA256_cose_identifier = -7;
    private static $_attestation_formats = array('fido-u2f', 'packed', 'android-key');

    public function __construct($binary) {
        $enc = CborDecoder::decode($binary);
        // validation
        if (!\is_array($enc) || !\array_key_exists('fmt', $enc)) {
            throw new WebAuthnException('invalid attestation format', WebAuthnException::INVALID_DATA);
        }

        if (!\in_array($enc['fmt'], self::$_attestation_formats)) {
            throw new WebAuthnException('invalid attestation format: ' . $enc['fmt'], WebAuthnException::INVALID_DATA);
        }

        if (!\array_key_exists('attStmt', $enc) || !\is_array($enc['attStmt'])) {
            throw new WebAuthnException('invalid attestation format (attStmt not available)', WebAuthnException::INVALID_DATA);
        }

        if (\array_key_exists('alg', $enc['attStmt']) && $enc['attStmt']['alg'] !== self::$_SHA256_cose_identifier) { // SHA256
            throw new WebAuthnException('only SHA256 acceptable but got: ' . $enc['attStmt']['alg'], WebAuthnException::INVALID_DATA);
        }

        if (!\array_key_exists('sig', $enc['attStmt']) || !\is_object($enc['attStmt']['sig']) || !($enc['attStmt']['sig'] instanceof ByteBuffer)) {
            throw new WebAuthnException('no signature found', WebAuthnException::INVALID_DATA);
        }

        if (!\array_key_exists('x5c', $enc['attStmt']) || !\is_array($enc['attStmt']['x5c']) || \count($enc['attStmt']['x5c']) < 1) {
            throw new WebAuthnException('invalid x5c certificate', WebAuthnException::INVALID_DATA);
        }

        if (!\is_object($enc['attStmt']['x5c'][0]) || !($enc['attStmt']['x5c'][0] instanceof ByteBuffer)) {
            throw new WebAuthnException('invalid x5c certificate', WebAuthnException::INVALID_DATA);
        }

        if (!\array_key_exists('authData', $enc) || !\is_object($enc['authData']) || !($enc['authData'] instanceof ByteBuffer)) {
            throw new WebAuthnException('no signature found', WebAuthnException::INVALID_DATA);
        }

        $this->_attestationFormat = $enc['fmt'];
        $this->_signature = $enc['attStmt']['sig']->getBinaryString();
        $this->_x5c = $enc['attStmt']['x5c'][0]->getBinaryString();
        $this->_authenticatorData = new AuthenticatorData($enc['authData']->getBinaryString());
    }

    /**
     * returns the attestation public key in PEM format
     * @return AuthenticatorData
     */
    public function getAuthenticatorData() {
        return $this->_authenticatorData;
    }

    /**
     * returns the key certificate in PEM format
     * @return string
     */
    public function getCertificatePem() {
        $pem = '-----BEGIN CERTIFICATE-----' . "\n";
        $pem .= \chunk_split(\base64_encode($this->_x5c), 64, "\n");
        $pem .= '-----END CERTIFICATE-----' . "\n";
        return $pem;
    }

    /**
     * checks validity of the signature
     * @param string $clientDataHash
     * @return bool
     * @throws WebAuthnException
     */
    public function validateAttestation($clientDataHash) {
        $pubkeyid = \openssl_pkey_get_public($this->getCertificatePem());
        $dataToVerify = null;

        if ($pubkeyid === false) {
            throw new WebAuthnException('invalid public key: ' . \openssl_error_string(), WebAuthnException::INVALID_PUBLIC_KEY);
        }

        if ($this->_attestationFormat === 'fido-u2f') {
            // Let verificationData be the concatenation of (0x00 || rpIdHash || clientDataHash || credentialId || publicKeyU2F)
            $dataToVerify = "\x00";
            $dataToVerify .= $this->_authenticatorData->getRpIdHash();
            $dataToVerify .= $clientDataHash;
            $dataToVerify .= $this->_authenticatorData->getCredentialId();
            $dataToVerify .= $this->_authenticatorData->getPublicKeyU2F();

        } else if ($this->_attestationFormat === 'packed' || $this->_attestationFormat === 'android-key') {
            // Verify that sig is a valid signature over the concatenation of authenticatorData and clientDataHash
            // using the attestation public key in attestnCert with the algorithm specified in alg.
            $dataToVerify = $this->_authenticatorData->getBinary();
            $dataToVerify .= $clientDataHash;

        } else {
            throw new WebAuthnException('invalid attestation format', WebAuthnException::INVALID_DATA);
        }

        // check certificate
        return \openssl_verify($dataToVerify, $this->_signature, $pubkeyid, OPENSSL_ALGO_SHA256) === 1;
    }

    /**
     * validates the certificate against root certificates
     * @param array $rootCas
     * @return boolean
     * @throws WebAuthnException
     */
    public function validateRootCertificate($rootCas) {
        $v = \openssl_x509_checkpurpose($this->getCertificatePem(), -1, $rootCas);
        if ($v === -1) {
            throw new WebAuthnException('error on validating certificate: ' . \openssl_error_string(), WebAuthnException::CERTIFICATE_NOT_TRUSTED);
        }
        return $v;
    }

    /**
     * checks if the RpId-Hash is valid
     * @param string$rpIdHash
     * @return bool
     */
    public function validateRpIdHash($rpIdHash) {
        return $rpIdHash === $this->_authenticatorData->getRpIdHash();
    }
}
