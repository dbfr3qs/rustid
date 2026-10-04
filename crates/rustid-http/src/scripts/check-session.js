// rustid's check session iframe (OpenID Connect Session Management 1.0,
// section 4.2). A relying party posts "<client_id> <session_state>"; the
// answer is "unchanged" when the session state recomputed from the browser's
// check session cookie matches, "changed" when it doesn't (or the cookie is
// gone), and "error" for a message that can't be checked.
(function () {
    "use strict";
    var cookieName = document.getElementById("cookie-name").textContent.trim();

    function sessionCookie() {
        var pairs = document.cookie.split(";");
        for (var i = 0; i < pairs.length; i++) {
            var pair = pairs[i].trim();
            var eq = pair.indexOf("=");
            if (eq > 0 && pair.substring(0, eq) === cookieName) {
                return pair.substring(eq + 1);
            }
        }
        return null;
    }

    // SHA-256 (FIPS 180-4) over the UTF-8 bytes of a string, in plain
    // JavaScript: WebCrypto isn't available on every origin or browser.
    var K = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ];

    function utf8(text) {
        var binary = unescape(encodeURIComponent(text));
        var bytes = [];
        for (var i = 0; i < binary.length; i++) {
            bytes.push(binary.charCodeAt(i));
        }
        return bytes;
    }

    function sha256(bytes) {
        var h = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
        var bitLength = bytes.length * 8;
        var padded = bytes.slice();
        padded.push(0x80);
        while (padded.length % 64 !== 56) {
            padded.push(0);
        }
        for (var shift = 56; shift >= 0; shift -= 8) {
            // Lengths beyond 2^32 bits never occur here.
            padded.push(shift >= 32 ? 0 : (bitLength >>> shift) & 0xff);
        }
        var w = new Array(64);
        for (var offset = 0; offset < padded.length; offset += 64) {
            for (var t = 0; t < 16; t++) {
                var j = offset + t * 4;
                w[t] = (padded[j] << 24) | (padded[j + 1] << 16) | (padded[j + 2] << 8) | padded[j + 3];
            }
            for (t = 16; t < 64; t++) {
                var x = w[t - 15], y = w[t - 2];
                var s0 = ((x >>> 7) | (x << 25)) ^ ((x >>> 18) | (x << 14)) ^ (x >>> 3);
                var s1 = ((y >>> 17) | (y << 15)) ^ ((y >>> 19) | (y << 13)) ^ (y >>> 10);
                w[t] = (w[t - 16] + s0 + w[t - 7] + s1) | 0;
            }
            var a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], k = h[7];
            for (t = 0; t < 64; t++) {
                var S1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
                var ch = (e & f) ^ (~e & g);
                var t1 = (k + S1 + ch + K[t] + w[t]) | 0;
                var S0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
                var maj = (a & b) ^ (a & c) ^ (b & c);
                var t2 = (S0 + maj) | 0;
                k = g; g = f; f = e; e = (d + t1) | 0; d = c; c = b; b = a; a = (t1 + t2) | 0;
            }
            h[0] = (h[0] + a) | 0; h[1] = (h[1] + b) | 0; h[2] = (h[2] + c) | 0; h[3] = (h[3] + d) | 0;
            h[4] = (h[4] + e) | 0; h[5] = (h[5] + f) | 0; h[6] = (h[6] + g) | 0; h[7] = (h[7] + k) | 0;
        }
        var out = [];
        for (var i = 0; i < 8; i++) {
            out.push((h[i] >>> 24) & 0xff, (h[i] >>> 16) & 0xff, (h[i] >>> 8) & 0xff, h[i] & 0xff);
        }
        return out;
    }

    function base64Url(bytes) {
        var text = "";
        for (var i = 0; i < bytes.length; i++) {
            text += String.fromCharCode(bytes[i]);
        }
        return btoa(text).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    }

    // As the authorize endpoint computes it: SHA-256 over the client id, the
    // relying party's origin, the session id and the salt, then ".salt".
    function sessionState(clientId, origin, sessionId, salt) {
        return base64Url(sha256(utf8(clientId + origin + sessionId + salt))) + "." + salt;
    }

    window.addEventListener("message", function (e) {
        if (!e.source || e.source === window || typeof e.data !== "string") {
            return;
        }
        function reply(status) {
            e.source.postMessage(status, e.origin);
        }
        var space = e.data.lastIndexOf(" ");
        var state = e.data.substring(space + 1);
        var dot = state.lastIndexOf(".");
        if (space <= 0 || dot < 0 || e.origin === "null") {
            reply("error");
            return;
        }
        var sessionId = sessionCookie();
        if (sessionId === null) {
            reply("changed");
            return;
        }
        var expected = sessionState(e.data.substring(0, space), e.origin, sessionId, state.substring(dot + 1));
        reply(expected === state ? "unchanged" : "changed");
    }, false);
})();
