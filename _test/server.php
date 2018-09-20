<?php

/* 
 * Copyright (C) 2018 Lukas Buchs
 * Alle Rechte vorbehalten.
 */

require_once '../WebAuthn.php';
try {
    session_start();


    $fn = $_GET['fn'];
    $post = trim(file_get_contents('php://input'));
    if ($post) {
        $post = json_decode($post);
    }

    $WebAuthn = new \WebAuthn\WebAuthn('SocialOffice', 'localhost');

    // request for create arguments
    if ($fn === 'getCreateArgs') {
        print(json_encode($WebAuthn->getCreateArgs('demo', 'demo', 'Demo Demolin')));
        $_SESSION['challenge'] = $WebAuthn->getChallenge();

    // request for get arguments
    } else if ($fn === 'getGetArgs') {
        $ids = array();

        if (is_array($_SESSION['registrations'])) {
            foreach ($_SESSION['registrations'] as $reg) {
                $ids[] = $reg->credentialId;
            }
        }

        print(json_encode($WebAuthn->getGetArgs($ids)));
        $_SESSION['challenge'] = $WebAuthn->getChallenge();

    // process create
    } else if ($fn === 'processCreate') {
        $clientDataJSON = base64_decode($post->clientDataJSON);
        $attestationObject = base64_decode($post->attestationObject);
        $challenge = $_SESSION['challenge'];
        $data = $WebAuthn->processCreate($clientDataJSON, $attestationObject, $challenge);

        if (!array_key_exists('registrations', $_SESSION) || !is_array($_SESSION['registrations'])) {
            $_SESSION['registrations'] = array();
        }

        $_SESSION['registrations'][] = $data;

        $return = new stdClass();
        $return->success = true;
        $return->msg = 'Registration Success. I have ' . count($_SESSION['registrations']) . ' registrations in session.';
        print(json_encode($return));

    // proccess get
    } else if ($fn === 'processGet') {
        $clientDataJSON = base64_decode($post->clientDataJSON);
        $authenticatorData = base64_decode($post->authenticatorData);
        $signature = base64_decode($post->signature);
        $id = base64_decode($post->id);
        $challenge = $_SESSION['challenge'];
        $credentialPublicKey = null;

        if (is_array($_SESSION['registrations'])) {
            foreach ($_SESSION['registrations'] as $reg) {
                if ($reg->credentialId === $id) {
                    $credentialPublicKey = $reg->credentialPublicKey;
                    break;
                }
            }
        }

        if ($credentialPublicKey === null) {
            throw new Exception('Public Key for ID not found!');
        }

        $WebAuthn->processGet($clientDataJSON, $authenticatorData, $signature, $credentialPublicKey, $challenge);

        $return = new stdClass();
        $return->success = true;
        print(json_encode($return));
    }
} catch (Throwable $ex) {
    $return = new stdClass();
    $return->success = false;
    $return->msg = $ex->getMessage();
    print(json_encode($return));
}

