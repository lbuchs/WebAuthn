<?php
namespace WebAuthn;

/**
 * @author Lukas Buchs
 */
class WebAuthnException extends \Exception {
    public function __construct($message = "", $code = 0, $previous = null) {
        parent::__construct($message, $code, $previous);
    }
}
