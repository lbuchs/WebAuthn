<?php

/* 
 * Copyright (C) 2018 Lukas Buchs
 * license https://github.com/lbuchs/WebAuthn/blob/master/LICENSE MIT
 *
 * Server test script for WebAuthn library. Saves new registrations in session.
 *
 *            JAVASCRIPT            |          SERVER
 * ------------------------------------------------------------
 *
 *               REGISTRATION
 *
 *      window.fetch  ----------------->     getCreateArgs
 *                                                |
 *   navigator.credentials.create   <-------------'
 *           |
 *           '------------------------->     processCreate
 *                                                |
 *         alert ok or fail      <----------------'
 *
 * ------------------------------------------------------------
 *
 *              VALIDATION
 *
 *      window.fetch ------------------>      getGetArgs
 *                                                |
 *   navigator.credentials.get   <----------------'
 *           |
 *           '------------------------->      processGet
 *                                                |
 *         alert ok or fail      <----------------'
 *
 * ------------------------------------------------------------
 */

require_once '../WebAuthn.php';
try {
    session_start();


    $fn = $_GET['fn'];
    $post = trim(file_get_contents('php://input'));
    if ($post) {
        $post = json_decode($post);
    }


    // new Instance of the server library.
    // make sure that $rpId is the domain name.
    $WebAuthn = new \WebAuthn\WebAuthn('WebAuthn Library', 'localhost');



    // ------------------------------------
    // request for create arguments
    // ------------------------------------
    
    if ($fn === 'getCreateArgs') {
        $createArgs = $WebAuthn->getCreateArgs('demo', 'demo', 'Demo Demolin');

        // make sure that binary data is transmited correctly to the browser
        $createArgs->publicKey->user->id = _binAsBase64Str($createArgs->publicKey->user->id);
        $createArgs->publicKey->challenge = _binAsBase64Str($createArgs->publicKey->challenge);


        print(json_encode($createArgs));

        // save challange to session. you have to deliver it to processGet later.
        $_SESSION['challenge'] = $WebAuthn->getChallenge();



    // ------------------------------------
    // request for get arguments
    // ------------------------------------

    } else if ($fn === 'getGetArgs') {
        $ids = array();

        // load registrations from session stored there by processCreate.
        // normaly you have to load the credential Id's for a username
        // from the database.
        if (is_array($_SESSION['registrations'])) {
            foreach ($_SESSION['registrations'] as $reg) {
                $ids[] = $reg->credentialId;
            }
        }

        if (count($ids) === 0) {
            throw new Exception('no registrations in session.');
        }

        $getArgs = $WebAuthn->getGetArgs($ids);

        // make sure that binary data is transmited correctly to the browser
        $getArgs->publicKey->challenge = _binAsBase64Str($getArgs->publicKey->challenge);
        foreach ($getArgs->publicKey->allowCredentials as &$allowedCredential) {
            $allowedCredential->id = _binAsBase64Str($allowedCredential->id);
        }
        unset ($allowedCredential);

        print(json_encode($getArgs));

        // save challange to session. you have to deliver it to processGet later.
        $_SESSION['challenge'] = $WebAuthn->getChallenge();



    // ------------------------------------
    // process create
    // ------------------------------------

    } else if ($fn === 'processCreate') {
        $clientDataJSON = base64_decode($post->clientDataJSON);
        $attestationObject = base64_decode($post->attestationObject);
        $challenge = $_SESSION['challenge'];

        // processCreate returns data to be stored for future logins.
        // in this example we store it in the php session.
        // Normaly you have to store the data in a database connected
        // with the user name.
        $data = $WebAuthn->processCreate($clientDataJSON, $attestationObject, $challenge);

        if (!array_key_exists('registrations', $_SESSION) || !is_array($_SESSION['registrations'])) {
            $_SESSION['registrations'] = array();
        }
        $_SESSION['registrations'][] = $data;

        $return = new stdClass();
        $return->success = true;
        $return->msg = 'Registration Success. I have ' . count($_SESSION['registrations']) . ' registrations in session.';
        print(json_encode($return));



    // ------------------------------------
    // proccess get
    // ------------------------------------

    } else if ($fn === 'processGet') {
        $clientDataJSON = base64_decode($post->clientDataJSON);
        $authenticatorData = base64_decode($post->authenticatorData);
        $signature = base64_decode($post->signature);
        $id = base64_decode($post->id);
        $challenge = $_SESSION['challenge'];
        $credentialPublicKey = null;

        // looking up correspondending public key of the credential id
        // you should also validate that only ids of the given user name
        // are taken for the login.
        if (is_array($_SESSION['registrations'])) {
            foreach ($_SESSION['registrations'] as $reg) {
                if ($reg->credentialId === $id) {
                    $credentialPublicKey = $reg->credentialPublicKey;
                    break;
                }
            }
        }

        if ($credentialPublicKey === null) {
            throw new Exception('Public Key for credential ID not found!');
        }

        // process the get request. throws WebAuthnException if it fails
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




/**
 * returns a string formated by RFC 1342
 * @param string $binary
 * @param string $charset
 * @return string
 */
function _binAsBase64Str($binary, $charset='') {
    // RFC 1342
    return '?' . $charset . '?B?' . \base64_encode($binary) . '?=';
}