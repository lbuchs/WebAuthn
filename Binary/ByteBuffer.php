<?php


namespace WebAuthn\Binary;
use WebAuthn\WebAuthnException;

/**
 * Modified version of https://github.com/madwizard-thomas/webauthn-server/blob/master/src/Format/ByteBuffer.php
 * Copyright © 2018 Thomas Bleeker - MIT licensed
 * Modified by Lukas Buchs
 * Thanks Thomas for your work!
 */
class ByteBuffer implements \JsonSerializable, \Serializable {
    /**
     * @var string
     */
    private $data;

    /**
     * @var int
     */
    private $length;

    public function __construct($binaryData) {
        $this->data = $binaryData;
        $this->length = \strlen($binaryData);
    }


    // -----------------------
    // PUBLIC STATIC
    // -----------------------

    public static function fromHex($hex) {
        $bin = \hex2bin($hex);
        if ($bin === false) {
            throw new WebAuthnException('ByteBuffer: Invalid hex string', WebAuthnException::BYTEBUFFER);
        }
        return new ByteBuffer($bin);
    }

    public static function randomBuffer($length) {
        if (\function_exists('random_bytes')) { // >PHP 7.0
            return new ByteBuffer(\random_bytes($length));

        } else if (\function_exists('openssl_random_pseudo_bytes')) {
            return new ByteBuffer(\openssl_random_pseudo_bytes($length));
            
        } else {
            throw new WebAuthnException('ByteBuffer: cannot generate random bytes', WebAuthnException::BYTEBUFFER);
        }
    }

    // -----------------------
    // PUBLIC
    // -----------------------

    public function getBytes($offset, $length) {
        if ($offset < 0 || $length < 0 || ($offset + $length > $this->length)) {
            throw new WebAuthnException('ByteBuffer: Invalid offset or length', WebAuthnException::BYTEBUFFER);
        }
        return \substr($this->data, $offset, $length);
    }

    public function getByteVal($offset) {
        if ($offset < 0 || $offset >= $this->length) {
            throw new WebAuthnException('ByteBuffer: Invalid offset', WebAuthnException::BYTEBUFFER);
        }
        return \ord(\substr($this->data, $offset, 1));
    }

    public function getLength() {
        return $this->length;
    }

    public function getUint16Val($offset) {
        if ($offset < 0 || ($offset + 2) > $this->length) {
            throw new WebAuthnException('ByteBuffer: Invalid offset', WebAuthnException::BYTEBUFFER);
        }
        return unpack('n', $this->data, $offset)[1];
    }

    public function getUint32Val($offset) {
        if ($offset < 0 || ($offset + 4) > $this->length) {
            throw new WebAuthnException('ByteBuffer: Invalid offset', WebAuthnException::BYTEBUFFER);
        }
        $val = unpack('N', $this->data, $offset)[1];
        
        // Signed integer overflow causes signed negative numbers
        if ($val < 0) {
            throw new WebAuthnException('ByteBuffer: Value out of integer range.', WebAuthnException::BYTEBUFFER);
        }
        return $val;
    }

    public function getUint64Val($offset) {
        if (PHP_INT_SIZE < 8) {
            throw new WebAuthnException('ByteBuffer: 64-bit values not supported by this system', WebAuthnException::BYTEBUFFER);
        }
        if ($offset < 0 || ($offset + 8) > $this->length) {
            throw new WebAuthnException('ByteBuffer: Invalid offset', WebAuthnException::BYTEBUFFER);
        }
        $val = unpack('J', $this->data, $offset)[1];

        // Signed integer overflow causes signed negative numbers
        if ($val < 0) {
            throw new WebAuthnException('ByteBuffer: Value out of integer range.', WebAuthnException::BYTEBUFFER);
        }

        return $val;
    }

    public function getHalfFloatVal($offset) {
        //FROM spec pseudo decode_half(unsigned char *halfp)
        $half = $this->getUint16Val($offset);

        $exp = ($half >> 10) & 0x1f;
        $mant = $half & 0x3ff;

        if ($exp === 0) {
            $val = $mant * (2 ** -24);
        } elseif ($exp !== 31) {
            $val = ($mant + 1024) * (2 ** ($exp - 25));
        } else {
            $val = ($mant === 0) ? INF : NAN;
        }

        return ($half & 0x8000) ? -$val : $val;
    }

    public function getFloatVal($offset) {
        if ($offset < 0 || ($offset + 4) > $this->length) {
            throw new WebAuthnException('ByteBuffer: Invalid offset', WebAuthnException::BYTEBUFFER);
        }
        return unpack('G', $this->data, $offset)[1];
    }

    public function getDoubleVal($offset) {
        if ($offset < 0 || ($offset + 8) > $this->length) {
            throw new WebAuthnException('ByteBuffer: Invalid offset', WebAuthnException::BYTEBUFFER);
        }
        return unpack('E', $this->data, $offset)[1];
    }

    /**
     * @return string
     */
    public function getBinaryString() {
        return $this->data;
    }

    /**
     * @param string $buffer
     * @return bool
     */
    public function equals($buffer) {
        return is_string($this->data) && $this->data === $buffer->data;
    }

    /**
     * @return string
     */
    public function getHex() {
        return \bin2hex($this->data);
    }

    /**
     * @return bool
     */
    public function isEmpty() {
        return $this->length === 0;
    }


    /**
     * jsonSerialize interface
     * @return \stdClass
     */
    public function jsonSerialize() {
        return '?BINARY?B?' . \base64_encode($this->data) . '?=';
    }

    /**
     * Das Serializable-Interface
     * @return string
     */
    public function serialize() {
        return \serialize($this->data);
    }

    /**
     * Das Serializable-Interface
     * @param string $serialized
     */
    public function unserialize($serialized) {
        $this->data = \unserialize($serialized);
        $this->length = \strlen($this->data);
    }
}
