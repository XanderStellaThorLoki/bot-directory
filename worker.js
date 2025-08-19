function pemToArrayBuffer(pem) {
  try {
    const pemHeader = "-----BEGIN PRIVATE KEY-----";
    const pemFooter = "-----END PRIVATE KEY-----";
    pem = pem.replace(pemHeader, "").replace(pemFooter, "").trim();
    const binaryDerString = atob(pem);
    const binaryDer = new Uint8Array(binaryDerString.length);
    for (let i = 0; i < binaryDerString.length; i++) {
      binaryDer[i] = binaryDerString.charCodeAt(i);
    }
    return binaryDer.buffer;
  } catch (error) {
    throw new Error("Failed to parse PEM: " + error.message);
  }
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname === '/.well-known/http-message-signatures-directory') {
      try {
        const jwks = {
          keys: [{
            kty: "RSA",
            n: "v1tGRStitNUsum3OVLS1QPLQk7eW9L8wjRt9047H7FssqSgSlQgjd98IIhTezbpPLNwgtvN7G6Gd5Hu4MTKDBWZwMxHDsw-9cROpRLEtrka9leYTQVI6AkGI-dBCLtMDO95dXHZpbu329H4stp_4NnKomVZ--lgzJ5RTYaXIDeBJcCTfO49_7Bjob9Vldmjtif2w2Y9gLNhNPuLbPi1_QnPjfkYAoX6Yx_bxqhMBsylpqham27yay7x2BYxSiiKLFXF1w188MIQCpk7Q24LuoMT5b8Qb6Y0oNap7y-YoTKdgfyDMMWu4WNyIN6LGJkohc73UAHHn_-SLDleay7Hp8Q",
            e: "AQAB"
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
        const params = `;alg="rsa-sha256";keyid="${thumbprint}";nonce="${nonce}";tag="http-message-signatures-directory";created=${created};expires=${expires}`;
        const sig_input = `sig1=${components}${params}`;
        const base = `"@authority": ${authority}\n"@signature-params": ${components}${params}`;
        const privateKeyPem = env.PRIVATE_KEY;
        if (!privateKeyPem) {
          throw new Error("PRIVATE_KEY secret is not set");
        }
        const privateKey = await crypto.subtle.importKey(
          "pkcs8",
          pemToArrayBuffer(privateKeyPem),
          { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
          false,
          ["sign"]
        );
        const sig_bytes = await crypto.subtle.sign(
          "RSASSA-PKCS1-v1_5",
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
      } catch (error) {
        console.error("Worker error: " + error.message);
        return new Response("Internal Server Error: " + error.message, { status: 500 });
      }
    }
    return new Response("Not found", { status: 404 });
  }
};