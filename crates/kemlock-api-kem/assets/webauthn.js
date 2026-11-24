// The /kem/v1/webauthn connector page's script. A Kemlock client that isn't a page of this server
// (the browser extension) opens the page with the request in the URL fragment, which never goes to
// a server; the page asks the person's passkey or security key for an answer, for this server's
// relying party, and hands the answer back to the extension, never anywhere else:
//
//   #options=<base64url JSON of the server's PublicKeyCredentialRequestOptions>
//   &state=<what the caller wants echoed, up to 256 URL-safe characters>
//   &redirect=<the extension's own redirect address, on the server's allowlist>
//   &extension=<a Chromium extension id on the allowlist, when the caller opened this page and
//               wants window.postMessage instead of a redirect>
//   &prf=0  (leave it out to also ask for the PRF output that opens the vault)
//
// The answer is a base64url JSON in `#result=...&state=...` of the redirect address, or in a
// message to the opener: { state, credential, prf? } or { state, error } where error is
// "cancelled", "unavailable" or "invalid". A person who dismisses the prompt can try again in the
// page; nothing is sent until there is an answer or a failure that retrying won't fix.
// No inline script: this file is the only script, and the page's CSP allows nothing else.
'use strict';

(function () {
  var CHROMIUM_HOST = '.chromiumapp.org';
  var FIREFOX_HOST = '.extensions.allizom.org';
  var REDIRECT_PATHS = ['/', '/sso'];
  var PRF_SALT = 'kemlock/v1/prf-salt';
  var STATE_PATTERN = /^[A-Za-z0-9._~-]{0,256}$/;
  var ID_PATTERN = /^[a-z0-9]{1,64}$/;

  var statusLine = document.getElementById('status');
  var retry = document.getElementById('retry');
  var meta = document.querySelector('meta[name="kemlock-extension-ids"]');
  var allowed = (meta ? meta.getAttribute('content') || '' : '')
    .split(',')
    .map(function (id) {
      return id.trim().toLowerCase();
    })
    .filter(function (id) {
      return ID_PATTERN.test(id);
    });

  function say(text) {
    statusLine.textContent = text;
  }

  function encode(bytes) {
    var text = '';
    for (var i = 0; i < bytes.length; i += 1) text += String.fromCharCode(bytes[i]);
    return btoa(text).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  function decode(text) {
    if (typeof text !== 'string' || !/^[A-Za-z0-9_-]*$/.test(text)) throw new Error('invalid');
    var padded = text.replace(/-/g, '+').replace(/_/g, '/');
    while (padded.length % 4 !== 0) padded += '=';
    var raw = atob(padded);
    var out = new Uint8Array(raw.length);
    for (var i = 0; i < raw.length; i += 1) out[i] = raw.charCodeAt(i);
    return out;
  }

  // Whether `text` is exactly an extension's redirect address that the admin named: https, the
  // Chromium or Firefox host of an id on the list, the path / or /sso, and nothing else. Anything
  // else, an unlisted id included, gets no answer, so another extension can't read it.
  // The address is rebuilt from the list's own id, host and path, never the caller's text, so
  // nothing the caller wrote reaches the redirect. `null` for anything else.
  function redirectTarget(text) {
    var url;
    try {
      url = new URL(text);
    } catch (e) {
      return null;
    }
    if (url.href !== text || url.protocol !== 'https:') return null;
    if (url.username || url.password || url.port || url.search || url.hash) return null;
    var path = REDIRECT_PATHS[REDIRECT_PATHS.indexOf(url.pathname)];
    if (path === undefined) return null;
    var host = url.hostname;
    var suffix = null;
    if (host.endsWith(CHROMIUM_HOST)) suffix = CHROMIUM_HOST;
    else if (host.endsWith(FIREFOX_HOST)) suffix = FIREFOX_HOST;
    if (suffix === null) return null;
    var id = allowed[allowed.indexOf(host.slice(0, -suffix.length))];
    if (id === undefined) return null;
    return 'https://' + id + suffix + path;
  }

  // Where the answer goes: a redirect on the allowlist, else the opener when it is an allowlisted
  // Chromium extension. `null` when the caller named neither, or one that isn't allowed.
  function deliveryOf(params) {
    var redirect = params.get('redirect');
    if (redirect !== null) {
      var target = redirectTarget(redirect);
      return target === null ? null : { redirect: target };
    }
    var id = params.get('extension');
    if (id && allowed.indexOf(id) >= 0 && window.opener) return { origin: 'chrome-extension://' + id };
    return null;
  }

  // The server sends options as `{ publicKey: {...} }` or bare, with every binary value base64url;
  // credentials.get wants buffers.
  function requestOptions(options) {
    var inner = options && typeof options.publicKey === 'object' && options.publicKey ? options.publicKey : options;
    if (!inner || typeof inner !== 'object') throw new Error('invalid');
    var result = Object.assign({}, inner);
    result.challenge = decode(inner.challenge);
    var list = Array.isArray(inner.allowCredentials) ? inner.allowCredentials : [];
    result.allowCredentials = list.map(function (entry) {
      return Object.assign({}, entry, { id: decode(entry.id) });
    });
    return result;
  }

  function encodeCredential(credential) {
    var response = credential.response;
    var out = {
      id: credential.id,
      rawId: encode(new Uint8Array(credential.rawId)),
      type: credential.type,
      response: {
        authenticatorData: encode(new Uint8Array(response.authenticatorData)),
        clientDataJSON: encode(new Uint8Array(response.clientDataJSON)),
        signature: encode(new Uint8Array(response.signature)),
      },
      clientExtensionResults: credential.getClientExtensionResults(),
    };
    if (credential.authenticatorAttachment) out.authenticatorAttachment = credential.authenticatorAttachment;
    if (response.userHandle) out.response.userHandle = encode(new Uint8Array(response.userHandle));
    return out;
  }

  async function ask(options, withPrf) {
    var publicKey = requestOptions(options);
    if (withPrf) {
      var salt = new TextEncoder().encode(PRF_SALT);
      var first = new Uint8Array(await crypto.subtle.digest('SHA-256', salt));
      publicKey.extensions = Object.assign({}, publicKey.extensions, { prf: { eval: { first: first } } });
    }
    var credential = await navigator.credentials.get({ publicKey: publicKey });
    if (!credential) throw new DOMException('no answer', 'NotAllowedError');
    var answer = { credential: encodeCredential(credential) };
    var results = credential.getClientExtensionResults();
    if (withPrf && results.prf && results.prf.results && results.prf.results.first) {
      answer.prf = encode(new Uint8Array(results.prf.results.first));
    }
    return answer;
  }

  function reason(error) {
    if (error && (error.name === 'NotAllowedError' || error.name === 'AbortError')) return 'cancelled';
    if (error && error.message === 'invalid') return 'invalid';
    return 'unavailable';
  }

  function deliver(delivery, state, payload) {
    var body = Object.assign({ state: state }, payload);
    if (delivery.redirect) {
      var text = encode(new TextEncoder().encode(JSON.stringify(body)));
      window.location.replace(delivery.redirect + '#result=' + text + (state ? '&state=' + encodeURIComponent(state) : ''));
      return;
    }
    window.opener.postMessage({ type: 'kemlock-webauthn', body: body }, delivery.origin);
    say('Done. You can close this tab.');
    window.close();
  }

  async function attempt(params, delivery, state) {
    retry.hidden = true;
    say('Waiting for your passkey or security key.');
    var payload;
    try {
      var options = JSON.parse(new TextDecoder().decode(decode(params.get('options') || '')));
      payload = await ask(options, params.get('prf') !== '0');
    } catch (error) {
      payload = { error: reason(error) };
    }
    if (payload.error === 'cancelled') {
      say('The passkey was not used.');
      retry.hidden = false;
      retry.onclick = function () {
        attempt(params, delivery, state);
      };
      return;
    }
    deliver(delivery, state, payload);
  }

  var params = new URLSearchParams(window.location.hash.replace(/^#/, ''));
  // The request is only for this page: keep it out of the history.
  window.history.replaceState(null, '', window.location.pathname);
  var state = params.get('state') || '';
  var delivery = deliveryOf(params);
  if (!delivery || !STATE_PATTERN.test(state)) {
    say('This page was opened without a valid way back to the extension, so it does nothing.');
  } else {
    attempt(params, delivery, state);
  }
})();
