<?php


namespace lbuchs\WebAuthn\Attestation\Format;
use lbuchs\WebAuthn\Attestation\AuthenticatorData;
use lbuchs\WebAuthn\WebAuthnException;

class None extends FormatBase {


    public function __construct($AttestionObject, AuthenticatorData $authenticatorData) {
        parent::__construct($AttestionObject, $authenticatorData);
    }


    /*
     * returns the key certificate in PEM format
     * @return string
     */
    public function getCertificatePem() {
        return null;
    }

    /**
     * @param string $clientDataHash
     */
    public function validateAttestation($clientDataHash) {
        // §8.7: attStmt must be an empty CBOR map for "none" format.
        if (\count($this->_attestationObject['attStmt']) > 0) {
            throw new WebAuthnException('invalid none attestation: attStmt must be empty', WebAuthnException::INVALID_DATA);
        }

        return true;
    }

    /**
     * validates the certificate against root certificates.
     * Format 'none' does not contain any ca, so always false.
     * @param array $rootCas
     * @return boolean
     * @throws WebAuthnException
     */
    public function validateRootCertificate($rootCas) {
        return false;
    }
}
