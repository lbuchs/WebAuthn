<?php


namespace WebAuthn\Attestation\Format;
use \WebAuthn\WebAuthnException;
use WebAuthn\Binary\ByteBuffer;


abstract class FormatBase {
    protected $_attestationObject = null;
    protected $_authenticatorData = null;

    /**
     *
     * @param Array $AttestionObject
     * @param \WebAuthn\Attestation\AuthenticatorData $authenticatorData
     */
    public function __construct($AttestionObject, \WebAuthn\Attestation\AuthenticatorData $authenticatorData) {
        $this->_attestationObject = $AttestionObject;
        $this->_authenticatorData = $authenticatorData;
    }

        /**
     * returns the key X.509 certificate in PEM format
     * @return string
     */
    public function getCertificatePem() {
        // need to be overwritten
        return null;
    }

    /**
     * checks validity of the signature
     * @param string $clientDataHash
     * @return bool
     * @throws WebAuthnException
     */
    public function validateAttestation($clientDataHash) {
        // need to be overwritten
        return false;
    }

    /**
     * validates the certificate against root certificates
     * @param array $rootCas
     * @return boolean
     * @throws WebAuthnException
     */
    public function validateRootCertificate($rootCas) {
        // need to be overwritten
        return false;
    }
}
