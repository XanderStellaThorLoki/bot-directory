function pemToArrayBuffer(pem) {
  const pemHeader = "-----BEGIN PRIVATE KEY-----";
  const pemFooter = "-----END PRIVATE KEY-----";
  pem = pem.replace(pemHeader, "").replace(pemFooter, "").trim();
  const binaryDerString = atob(pem);
  const binaryDer = new Uint8Array(binaryDerString.length);
  for (let i = 0; i < binaryDerString.length; i++) {
    binaryDer[i] = binaryDerString.charCodeAt(i);
  }
  return binaryDer.buffer;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname === '/.well-known/http-message-signatures-directory') {
      const jwks = {
        keys: [{
          kty: "OKP",
          crv: "Ed25519",
          x: "2guUk59QXxMbj9lCGH5Qj1YfjYpHRcVnkpNe-RXIOE4"
        }]
      };
      const body = JSON.stringify(jwks);
      const jwk = jwks.keys[0];
      const jwk_str = JSON.stringify(jwk, Object.keys(jwk).sort(), '');
      const thumb_hash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(jwk_str));
      const thumbprint = btoa(String.fromCharCode(...new Uint8Array(thumb_hash)))
        .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
      const authority = url.host;
      const created = Math.floor(Date.now() / 1000);
      const expires = created + 60;
      const nonce = crypto.randomUUID();
      const components = '("@authority")';
      const params = `;alg="ed25519";keyid="${thumbprint}";nonce="${nonce}";tag="http-message-signatures-directory";created=${created};expires=${expires}`;
      const sig_input = `sig1=${components}${params}`;
      const base = `"@authority": ${authority}\n"@signature-params": ${components}${params}`;
      const privateKeyPem = env.PRIVATE_KEY;
      const privateKey = await crypto.subtle.importKey(
        "pkcs8",
        pemToArrayBuffer(privateKeyPem),
        { name: "EdDSA", namedCurve: "Ed25519" },
        false,
        ["sign"]
      );
      const sig_bytes = await crypto.subtle.sign(
        "EdDSA",
        privateKey,
        new TextEncoder().encode(base)
      );
      const sig = btoa(String.fromCharCode(...new Uint8Array(sig_bytes)))
        .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
      const headers = new Headers({
        "Content-Type": "application/http-message-signatures-directory+json",
        "Signature-Input": sig_input,
        "Signature": `sig1=:${sig}:`,
        "Cache-Control": "max-age=86400"
      });
      return new Response(body, { headers });
    }
    return new Response("Not found", { status: 404 });
  }
};