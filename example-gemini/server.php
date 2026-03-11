<?php
/**
 * Passkey / WebAuthn Server Example using SQLite
 * 
 * Demonstrates:
 * - Registration
 * - Username-bound Login
 * - Usernameless Login (Discoverable Credentials)
 * - Security features (CSRF checks, safe JSON parsing, Base64 handling)
 */

// Define the path to the lbuchs/WebAuthn library.
// Adjust this path if integrating directly into your own project structure.

require_once __DIR__ . '/../src/WebAuthn.php';

session_start();

header('Content-Type: application/json');

// Connect to SQLite Database and ensure tables exist
// Using native SQLite3 class instead of PDO to ensure broader compatibility out-of-the-box
try {
    $db = new SQLite3(__DIR__ . '/passkeys.sqlite');
    $db->enableExceptions(true);

    $db->exec("CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL
    )");

    $db->exec("CREATE TABLE IF NOT EXISTS passkeys (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        credential_id TEXT UNIQUE NOT NULL,
        public_key TEXT NOT NULL,
        user_handle TEXT NOT NULL,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )");

} catch (Exception $e) {
    echo json_encode(['success' => false, 'msg' => 'Database connection failed: ' . $e->getMessage()]);
    exit;
}

$fn = $_GET['fn'] ?? '';
$rpId = $_SERVER['HTTP_HOST'] ?? 'localhost';
if (strpos($rpId, ':') !== false) {
    $rpId = explode(':', $rpId)[0]; // Remove port if present
}

try {
    $WebAuthn = new \lbuchs\WebAuthn\WebAuthn('Passkey Example App', $rpId, ['android-key', 'android-safetynet', 'apple', 'fido-u2f', 'none', 'packed', 'tpm']);

    if ($fn === 'getCreateArgs') {
        $username = filter_input(INPUT_GET, 'username', FILTER_SANITIZE_SPECIAL_CHARS);
        if (!$username) {
            throw new Exception('Username required for registration.');
        }

        // Get or create user
        $stmt = $db->prepare("SELECT id FROM users WHERE username = ?");
        $stmt->bindValue(1, $username);
        $result = $stmt->execute();
        $user = $result->fetchArray(SQLITE3_ASSOC);

        if (!$user) {
            $stmt = $db->prepare("INSERT INTO users (username) VALUES (?)");
            $stmt->bindValue(1, $username);
            $stmt->execute();
            $userId = $db->lastInsertRowID();
        } else {
            $userId = $user['id'];
        }

        // Store active registration attempt in session
        $_SESSION['register_user_id'] = $userId;
        $_SESSION['register_username'] = $username;

        // Generate binary user handle
        $userHandle = hash('sha256', (string)$userId, true);
        
        // $requireResidentKey = true ensures "Usernameless Login" works
        $createArgs = $WebAuthn->getCreateArgs($userHandle, $username, $username, 60*4, true, 'preferred');
        
        $_SESSION['webauthn_challenge'] = $WebAuthn->getChallenge();
        echo json_encode($createArgs);

    } elseif ($fn === 'processCreate') {
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
            throw new Exception('POST required.');
        }
        if (strpos($_SERVER['CONTENT_TYPE'] ?? '', 'application/json') === false) {
            throw new Exception('Invalid Content-Type. Must be application/json.');
        }
        
        $post = json_decode(file_get_contents('php://input'));
        $clientDataJSON = base64_decode($post->clientDataJSON ?? '');
        $attestationObject = base64_decode($post->attestationObject ?? '');
        $challenge = $_SESSION['webauthn_challenge'] ?? '';

        $data = $WebAuthn->processCreate($clientDataJSON, $attestationObject, $challenge, false, true, false);

        if (!isset($_SESSION['register_user_id'])) {
            throw new Exception('Registration session expired.');
        }

        $userId = $_SESSION['register_user_id'];
        $credentialId = base64_encode($data->credentialId);
        $publicKey = $data->credentialPublicKey;
        $userHandle = base64_encode(hash('sha256', (string)$userId, true));

        $stmt = $db->prepare("INSERT INTO passkeys (user_id, credential_id, public_key, user_handle) VALUES (?, ?, ?, ?)");
        $stmt->bindValue(1, $userId);
        $stmt->bindValue(2, $credentialId);
        $stmt->bindValue(3, $publicKey);
        $stmt->bindValue(4, $userHandle);
        $stmt->execute();

        // Clean up session
        unset($_SESSION['register_user_id']);
        unset($_SESSION['register_username']);

        echo json_encode(['success' => true, 'msg' => 'Registration successful! You can now log in.']);

    } elseif ($fn === 'getGetArgs') {
        $username = filter_input(INPUT_GET, 'username', FILTER_SANITIZE_SPECIAL_CHARS);
        $ids = [];

        // If username is provided, filter allowed passkeys to that specific user.
        // If empty, the array remains empty, prompting a Discoverable Credential (usernameless) login.
        if ($username) {
            $stmt = $db->prepare("SELECT p.credential_id FROM passkeys p JOIN users u ON p.user_id = u.id WHERE u.username = ?");
            $stmt->bindValue(1, $username);
            $result = $stmt->execute();
            while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
                $ids[] = base64_decode($row['credential_id']);
            }
        }

        $getArgs = $WebAuthn->getGetArgs($ids, 60*4, true, true, true, true, true, 'preferred');
        $_SESSION['webauthn_challenge'] = $WebAuthn->getChallenge();
        
        echo json_encode($getArgs);

    } elseif ($fn === 'processGet') {
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
            throw new Exception('POST required.');
        }
        if (strpos($_SERVER['CONTENT_TYPE'] ?? '', 'application/json') === false) {
            throw new Exception('Invalid Content-Type. Must be application/json.');
        }

        $post = json_decode(file_get_contents('php://input'));
        $clientDataJSON = base64_decode($post->clientDataJSON ?? '');
        $authenticatorData = base64_decode($post->authenticatorData ?? '');
        $signature = base64_decode($post->signature ?? '');
        $userHandle = base64_decode($post->userHandle ?? '');
        $id = base64_decode($post->id ?? '');
        
        $challenge = $_SESSION['webauthn_challenge'] ?? '';
        $credentialId = base64_encode($id);

        $stmt = $db->prepare("SELECT u.username, p.public_key FROM passkeys p JOIN users u ON p.user_id = u.id WHERE p.credential_id = ?");
        $stmt->bindValue(1, $credentialId);
        $result = $stmt->execute();
        $row = $result->fetchArray(SQLITE3_ASSOC);

        if ($row) {
            $WebAuthn->processGet($clientDataJSON, $authenticatorData, $signature, $row['public_key'], $challenge, null, false);
            
            // Login success - in a real app, initialize user session here.
            $_SESSION['logged_in_user'] = $row['username'];
            
            echo json_encode(['success' => true, 'msg' => 'Successfully logged in as ' . $row['username'] . '!']);
        } else {
            throw new Exception('Passkey not found in the database.');
        }

    } else {
        throw new Exception('Unknown function.');
    }

} catch (Throwable $e) {
    // Catching Throwable ensures Fatal Errors (like TypeErrors) are also returned as valid JSON
    echo json_encode(['success' => false, 'msg' => $e->getMessage()]);
}
