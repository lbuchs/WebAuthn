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


    private static $_attestation_format = 'fido-u2f';

    public function __construct($binary) {
        $enc = CborDecoder::decode($binary);

        // validation
        if (!\is_array($enc)) {
            throw new WebAuthnException('invalid attestation format', WebAuthnException::INVALID_DATA);
        }

        if (!\array_key_exists('fmt', $enc) || $enc['fmt'] !== self::$_attestation_format || !\array_key_exists('attStmt', $enc) || !\is_array($enc['attStmt'])) {
            throw new WebAuthnException('invalid attestation format', WebAuthnException::INVALID_DATA);
        }

        if (!\array_key_exists('sig', $enc['attStmt']) || !\is_object($enc['attStmt']['sig']) || !($enc['attStmt']['sig'] instanceof ByteBuffer)) {
            throw new WebAuthnException('no signature found', WebAuthnException::INVALID_DATA);
        }

        if (!\array_key_exists('x5c', $enc['attStmt']) || !\is_array($enc['attStmt']['x5c']) || \count($enc['attStmt']['x5c']) !== 1) {
            throw new WebAuthnException('invalid x5c certificate', WebAuthnException::INVALID_DATA);
        }

        if (!\is_object($enc['attStmt']['x5c'][0]) || !($enc['attStmt']['x5c'][0] instanceof ByteBuffer)) {
            throw new WebAuthnException('invalid x5c certificate', WebAuthnException::INVALID_DATA);
        }

        if (!\array_key_exists('authData', $enc) || !\is_object($enc['authData']) || !($enc['authData'] instanceof ByteBuffer)) {
            throw new WebAuthnException('no signature found', WebAuthnException::INVALID_DATA);
        }

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

        if ($pubkeyid === false) {
            throw new WebAuthnException('invalid public key: ' . \openssl_error_string(), WebAuthnException::INVALID_PUBLIC_KEY);
        }

        $dataToVerify = "\x00";
        $dataToVerify .= $this->_authenticatorData->getRpIdHash();
        $dataToVerify .= $clientDataHash;
        $dataToVerify .= $this->_authenticatorData->getCredentialId();
        $dataToVerify .= $this->_authenticatorData->getPublicKeyU2F();

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
