<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WebAuthn Passkey Example</title>
    <style>
        body { font-family: system-ui, sans-serif; max-width: 600px; margin: 40px auto; padding: 20px; line-height: 1.6; }
        .box { border: 1px solid #ddd; padding: 20px; margin-bottom: 20px; border-radius: 8px; background: #fafafa; }
        button { padding: 10px 15px; cursor: pointer; background: #007bff; color: white; border: none; border-radius: 4px; font-size: 1em; width: 100%; }
        button:hover { background: #0056b3; }
        input { padding: 10px; margin-bottom: 15px; width: 100%; box-sizing: border-box; border: 1px solid #ccc; border-radius: 4px; font-size: 1em; }
        #message { margin-top: 20px; padding: 15px; border-radius: 4px; display: none; font-weight: bold; text-align: center; }
        .success { background-color: #d4edda; color: #155724; border: 1px solid #c3e6cb; }
        .error { background-color: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; }
        .hint { font-size: 0.85em; color: #666; margin-top: -10px; margin-bottom: 15px; display: block; }
    </style>
</head>
<body>
    <h2>Passkey Example (SQLite)</h2>
    <p>This example demonstrates how to implement secure, modern Passkeys using the <code>lbuchs/WebAuthn</code> library.</p>

    <div id="message"></div>

    <div class="box">
        <h3>1. Register</h3>
        <input type="text" id="reg-username" placeholder="Choose a username (e.g., alice)">
        <button onclick="register()">Register Passkey</button>
    </div>

    <div class="box">
        <h3>2. Login</h3>
        <input type="text" id="login-username" placeholder="Username (optional)">
        <span class="hint">Leave blank for Usernameless Login (Discoverable Credentials).</span>
        <button onclick="login()">Login with Passkey</button>
    </div>

    <script>
        function showMessage(text, isError = false) {
            const msgEl = document.getElementById('message');
            msgEl.textContent = text;
            msgEl.className = isError ? 'error' : 'success';
            msgEl.style.display = 'block';
        }

        /**
         * Recursively searches for WebAuthn binary markers and decodes Base64URL to ArrayBuffer
         */
        function recursiveBase64StrToArrayBuffer(obj) {
            let prefix = '=?BINARY?B?';
            let suffix = '?=';
            if (typeof obj === 'object') {
                for (let key in obj) {
                    if (typeof obj[key] === 'string') {
                        let str = obj[key];
                        if (str.substring(0, prefix.length) === prefix && str.substring(str.length - suffix.length) === suffix) {
                            str = str.substring(prefix.length, str.length - suffix.length);
                            
                            // Normalize Base64URL to standard Base64
                            str = str.replace(/-/g, '+').replace(/_/g, '/');
                            while (str.length % 4 !== 0) str += '=';
                            
                            let binary_string = window.atob(str);
                            let len = binary_string.length;
                            let bytes = new Uint8Array(len);
                            for (let i = 0; i < len; i++) bytes[i] = binary_string.charCodeAt(i);
                            obj[key] = bytes.buffer;
                        }
                    } else {
                        recursiveBase64StrToArrayBuffer(obj[key]);
                    }
                }
            }
        }

        /**
         * Encodes ArrayBuffer to Base64 safely
         */
        function arrayBufferToBase64(buffer) {
            if (!buffer) return null;
            let binary = '';
            let bytes = new Uint8Array(buffer);
            for (let i = 0; i < bytes.byteLength; i++) binary += String.fromCharCode(bytes[i]);
            try {
                return window.btoa(binary);
            } catch (e) {
                return null;
            }
        }

        let preloadedGetArgs = null;
        
        // Preload generic challenge to bypass iOS Safari's strict user-gesture timeout
        window.addEventListener('load', async () => {
            if (window.fetch && navigator.credentials) {
                try {
                    let rep = await fetch('server.php?fn=getGetArgs', { cache: 'no-cache' });
                    let repText = await rep.text();
                    preloadedGetArgs = JSON.parse(repText);
                } catch(e) {}
            }
        });

        async function register() {
            try {
                if (!window.isSecureContext) {
                    throw new Error("WebAuthn requires a secure context (HTTPS or localhost).");
                }
                if (!window.fetch || !navigator.credentials || !navigator.credentials.create) {
                    throw new Error("Your browser or device does not support WebAuthn Passkeys.");
                }

                const username = document.getElementById('reg-username').value.trim();
                if (!username) throw new Error("A username is required for registration.");

                // 1. Get creation arguments from server
                let rep = await fetch(`server.php?fn=getCreateArgs&username=${encodeURIComponent(username)}`, { cache: 'no-cache' });
                let repText = await rep.text();
                let createArgs;
                try { createArgs = JSON.parse(repText); } catch(e) { throw new Error('Server error: ' + repText.substring(0, 100)); }
                
                if (createArgs.success === false) throw new Error(createArgs.msg);

                // 2. Ask the browser to create the credential
                recursiveBase64StrToArrayBuffer(createArgs);
                const cred = await navigator.credentials.create(createArgs);

                const response = {
                    clientDataJSON: cred.response.clientDataJSON ? arrayBufferToBase64(cred.response.clientDataJSON) : null,
                    attestationObject: cred.response.attestationObject ? arrayBufferToBase64(cred.response.attestationObject) : null
                };

                // 3. Send the new credential to the server to verify and store
                rep = await fetch('server.php?fn=processCreate', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(response),
                    cache: 'no-cache'
                });
                
                repText = await rep.text();
                let result;
                try { result = JSON.parse(repText); } catch(e) { throw new Error('Server error: ' + repText.substring(0, 100)); }
                
                if (!result.success) throw new Error(result.msg);
                showMessage(result.msg);
                document.getElementById('reg-username').value = ''; // clear
            } catch (e) {
                showMessage(e.message, true);
            }
        }

        async function login() {
            try {
                if (!window.isSecureContext) {
                    throw new Error("WebAuthn requires a secure context (HTTPS or localhost).");
                }
                if (!window.fetch || !navigator.credentials || !navigator.credentials.create) {
                    throw new Error("Your browser or device does not support WebAuthn Passkeys.");
                }

                const username = document.getElementById('login-username').value.trim();
                let getArgs;

                if (username) {
                    // 1. Get assertion arguments from server
                    let url = 'server.php?fn=getGetArgs&username=' + encodeURIComponent(username);
                    let rep = await fetch(url, { cache: 'no-cache' });
                    let repText = await rep.text();
                    try { getArgs = JSON.parse(repText); } catch(e) { throw new Error('Server error: ' + repText.substring(0, 100)); }
                } else if (preloadedGetArgs) {
                    // Instantly use preloaded args for zero latency (satisfies iOS user-gesture requirements)
                    getArgs = JSON.parse(JSON.stringify(preloadedGetArgs));
                } else {
                    let rep = await fetch('server.php?fn=getGetArgs', { cache: 'no-cache' });
                    let repText = await rep.text();
                    try { getArgs = JSON.parse(repText); } catch(e) { throw new Error('Server error: ' + repText.substring(0, 100)); }
                }
                
                if (getArgs.success === false) throw new Error(getArgs.msg);

                // 2. Ask the browser to prompt the user to authenticate
                recursiveBase64StrToArrayBuffer(getArgs);
                const cred = await navigator.credentials.get(getArgs);

                const response = {
                    id: cred.rawId ? arrayBufferToBase64(cred.rawId) : null,
                    clientDataJSON: cred.response.clientDataJSON ? arrayBufferToBase64(cred.response.clientDataJSON) : null,
                    authenticatorData: cred.response.authenticatorData ? arrayBufferToBase64(cred.response.authenticatorData) : null,
                    signature: cred.response.signature ? arrayBufferToBase64(cred.response.signature) : null,
                    userHandle: cred.response.userHandle ? arrayBufferToBase64(cred.response.userHandle) : null
                };

                // 3. Send the signature to the server to verify
                rep = await fetch('server.php?fn=processGet', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(response),
                    cache: 'no-cache'
                });
                
                repText = await rep.text();
                let result;
                try { result = JSON.parse(repText); } catch(e) { throw new Error('Server error: ' + repText.substring(0, 100)); }
                
                if (!result.success) throw new Error(result.msg);
                showMessage(result.msg);
            } catch (e) {
                showMessage(e.message, true);
            }
        }
    </script>
</body>
</html>