<?php

namespace WebAuthn\Attestation;

/**
 * @author Lukas Buchs
 */
class AttestationObject {
    private $_signature;
    private $_x5c;
    private $_authenticatorData;


    private static $_attestation_format = 'fido-u2f';

    public function __construct($binary) {
        require_once '../CBOR/CBOREncoder.php';
        require_once 'AuthenticatorData.php';
        
        $enc = \WebAuthn\CBOR\CBOREncoder::decode($binary);

        // validation
        if (!is_array($enc)) {
            throw new Exception('invalid attestation format');
        }

        if (!array_key_exists('fmt', $enc) || $enc['fmt'] !== self::$_attestation_format || !array_key_exists('attStmt', $enc) || !is_array($enc['attStmt'])) {
            throw new Exception('invalid attestation format');
        }

        if (!array_key_exists('sig', $enc['attStmt']) || !is_object($enc['attStmt']['sig']) || !($enc['attStmt']['sig'] instanceof \WebAuthn\CBOR\Types\CBORByteString)) {
            throw new Exception('no signature found');
        }

        if (!array_key_exists('x5c', $enc['attStmt']) || !is_array($enc['attStmt']['x5c']) || count($enc['attStmt']['x5c']) !== 1) {
            throw new Exception('invalid x5c certificate');
        }

        if (!!is_object($enc['attStmt']['x5c'][0]) || !($enc['attStmt']['x5c'][0] instanceof \WebAuthn\CBOR\Types\CBORByteString)) {
            throw new Exception('invalid x5c certificate');
        }

        if (!array_key_exists('authData', $enc) || !is_object($enc['authData']) || !($enc['authData'] instanceof \WebAuthn\CBOR\Types\CBORByteString)) {
            throw new Exception('no signature found');
        }

        $this->_signature = $enc['attStmt']['sig']->get_byte_string();
        $this->_x5c = $enc['attStmt']['x5c'][0]->get_byte_string();
        $this->_authenticatorData = new AuthenticatorData($enc['authData']->get_byte_string());
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
        $pem .= chunk_split(base64_encode($this->_x5c), 64, "\n");
        $pem .= '-----BEGIN CERTIFICATE-----' . "\n";
        return $pem;
    }

    /**
     * checks validity of the signature
     * @param string $clientDataHash
     * @return bool
     * @throws Exception
     */
    public function validateAttestation($clientDataHash) {
        $pubkeyid = openssl_pkey_get_public($this->getCertificatePem());
        if ($pubkeyid === false) {
            throw new Exception('invalid public key');
        }

        $dataToVerify = "\x00";
        $dataToVerify .= $this->_authenticatorData->getRpIdHash();
        $dataToVerify .= $clientDataHash;
        $dataToVerify .= $this->_authenticatorData->getCredentialId();
        $dataToVerify .= $this->_authenticatorData->getPublicKeyU2F();

        // check certificate
        return openssl_verify($dataToVerify, $this->_signature, $pubkeyid, OPENSSL_ALGO_SHA256) === 1;
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
