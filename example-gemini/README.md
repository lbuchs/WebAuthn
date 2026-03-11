# WebAuthn Passkeys Example with SQLite

Simple example implementation of Passkeys using the `lbuchs/WebAuthn` library, using a SQLite database.

## Features Showcased
- **Registration**: Creating a new passkey bound to a username.
- **Username-bound Login**: Logging in by typing the username and prompting for the specific passkey.
- **Usernameless Login (Discoverable Credentials)**: Logging in without typing a username by letting the device identify the user automatically.
- **Seamless Database Integration**: Uses a standard `users` and `passkeys` table schema to manage multiple keys per user.

## Modern Security Enhancements Included
This example incorporates crucial security and reliability fixes for modern browsers:
- **CSRF Protection**: Enforces `Content-Type: application/json` on all POST endpoints, protecting against cross-origin malicious form submissions.
- **Robust Base64URL Handling**: Client-side JavaScript gracefully normalizes Base64URL encoding (converting `-`/`_` and re-applying `=` padding) to prevent `window.atob()` crash exceptions on iOS Safari.
- **Safe JSON Parsing & Type Safety**: Exceptions are rigorously caught and returned as JSON, preventing `JSON.parse` failures on the client side when PHP encounters silent warnings or `TypeErrors` (e.g., when authenticators omit optional fields like `userHandle`).
- **Enumeration Protection**: Generating the login challenge does not reveal whether a given username actually exists in the database.
- **Session Deserialization Safety**: The WebAuthn library (`WebAuthn.php`) is loaded *before* calling `session_start()`. Because the library stores complex objects (like `ByteBuffer`) in the PHP `$_SESSION` array, PHP must know about the class definition before deserializing the session data, otherwise it will result in a fatal `__PHP_Incomplete_Class` serialization error.
- **iOS 15.8.6 Safari Workaround**: Preloads the Usernameless login challenge asynchronously when the page loads. This bypasses Safari's extremely strict user-gesture timeouts which would otherwise silently cancel the Face ID/Touch ID prompt with a "This request has been canceled by the user" error if the server response takes too long.

Server tested with PHP-8.2.30 and sqlite3 enabled in PHP.
Client tested: Firefox and KeePassXC, iOS-15.8.6