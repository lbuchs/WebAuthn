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

    // read get argument and post body
    $fn = $_GET['fn'];
    $requireResidentKey = !!$_GET['requireResidentKey'];
    $post = trim(file_get_contents('php://input'));
    if ($post) {
        $post = json_decode($post);
    }

    // Formats
    $formats = array();
    if ($_GET['fmt_android-key']) {
        $formats[] = 'android-key';
    }
    if ($_GET['fmt_android-safetynet']) {
        $formats[] = 'android-safetynet';
    }
    if ($_GET['fmt_fido-u2f']) {
        $formats[] = 'fido-u2f';
    }
    if ($_GET['fmt_none']) {
        $formats[] = 'none';
    }
    if ($_GET['fmt_packed']) {
        $formats[] = 'packed';
    }
    if ($_GET['fmt_tpm']) {
        $formats[] = 'tpm';
    }

    $rpId = 'localhost';
    if ($_GET['rpId']) {
        $rpId = filter_input(INPUT_GET, 'rpId', FILTER_VALIDATE_DOMAIN);
        if ($rpId === false) {
            throw new Exception('invalid relying party ID');
        }
    }

    // new Instance of the server library.
    // make sure that $rpId is the domain name.
    $WebAuthn = new \WebAuthn\WebAuthn('WebAuthn Library', $rpId, $formats);

    // add root certificates to validate new registrations
    if ($_GET['solo']) {
        $WebAuthn->addRootCertificates('rootCertificates/solo.pem');
    }
    if ($_GET['yubico']) {
        $WebAuthn->addRootCertificates('rootCertificates/yubico.pem');
    }
    if ($_GET['hypersecu']) {
        $WebAuthn->addRootCertificates('rootCertificates/hypersecu.pem');
    }
    if ($_GET['google']) {
        $WebAuthn->addRootCertificates('rootCertificates/globalSign.pem');
        $WebAuthn->addRootCertificates('rootCertificates/googleHardware.pem');
    }


    // ------------------------------------
    // request for create arguments
    // ------------------------------------

    if ($fn === 'getCreateArgs') {
        $createArgs = $WebAuthn->getCreateArgs('demo', 'demo', 'Demo Demolin', 20, $requireResidentKey);

        print(json_encode($createArgs));

        // save challange to session. you have to deliver it to processGet later.
        $_SESSION['challenge'] = $WebAuthn->getChallenge();



    // ------------------------------------
    // request for get arguments
    // ------------------------------------

    } else if ($fn === 'getGetArgs') {
        $ids = array();

        if ($requireResidentKey) {
            if (!is_array($_SESSION['registrations']) || count($_SESSION['registrations']) === 0) {
                throw new Exception('we do not have any registrations in session to check the registration');
            }

        } else {
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
        }

        $getArgs = $WebAuthn->getGetArgs($ids);

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

    // ------------------------------------
    // proccess clear registrations
    // ------------------------------------

    } else if ($fn === 'clearRegistrations') {
        $_SESSION['registrations'] = null;
        $_SESSION['challenge'] = null;

        $return = new stdClass();
        $return->success = true;
        $return->msg = 'all registrations deleted';
        print(json_encode($return));
    }

} catch (Throwable $ex) {
    $return = new stdClass();
    $return->success = false;
    $return->msg = $ex->getMessage();
    print(json_encode($return));
}