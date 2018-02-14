/*
 * Licensed to Elasticsearch under one or more contributor
 * license agreements. See the NOTICE file distributed with
 * this work for additional information regarding copyright
 * ownership. Elasticsearch licenses this file to you under
 * the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package io.polyglotted.esjwt.impl;

import org.apache.commons.codec.binary.Base64;
import org.apache.http.HttpException;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static io.polyglotted.esjwt.impl.CommonUtil.deepGet;
import static io.polyglotted.esjwt.impl.CommonUtil.httpClient;
import static io.polyglotted.esjwt.impl.CommonUtil.parseJson;
import static io.polyglotted.esjwt.impl.CommonUtil.readFrom;

public abstract class JwtVerifier {
    private static final String RSA = "RSA";
    private static final String RSA_ALGO = "SHA256withRSA";

    public static void verifyRs256(String jwksUrl, JsonWebToken token) throws VerificationException {
        Map<String, Object> key = fetchJwks(jwksUrl).get(token.keyCode());
        if (key == null) { throw new VerificationException("could not find public key for " + token.keyCode()); }

        PublicKey publicKey = getPublicKey(deepGet(key, "kty"), deepGet(key, "n"), deepGet(key, "e"));
        if (publicKey == null) { return; }
        if (!verifySignatureFor(publicKey, token.contentBytes(), token.signatureBytes())) {
            throw new VerificationException("invalid signature");
        }
    }

    private static boolean verifySignatureFor(PublicKey publicKey, byte[] contentBytes, byte[] signatureBytes)
        throws VerificationException {
        try {
            Signature s = Signature.getInstance(RSA_ALGO);
            s.initVerify(publicKey);
            s.update(contentBytes);
            return s.verify(signatureBytes);
        } catch (NoSuchAlgorithmException | SignatureException | InvalidKeyException ex) {
            throw new VerificationException("failed signature verify", ex);
        }
    }

    private static PublicKey getPublicKey(String type, String nVal, String eVal) throws VerificationException {
        if (!RSA.equalsIgnoreCase(type)) { return null; }
        try {
            KeyFactory kf = KeyFactory.getInstance(RSA);
            BigInteger modulus = new BigInteger(1, Base64.decodeBase64(nVal));
            BigInteger exponent = new BigInteger(1, Base64.decodeBase64(eVal));
            return kf.generatePublic(new RSAPublicKeySpec(modulus, exponent));

        } catch (InvalidKeySpecException | NoSuchAlgorithmException ex) {
            throw new VerificationException("Unable to generate public key", ex);
        }
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Map<String, Object>> fetchJwks(String uri) throws VerificationException {
        Map<String, Map<String, Object>> result = new LinkedHashMap<>();
        try (CloseableHttpClient httpClient = httpClient()) {
            Map<String, Object> map = parseJson(readFrom(httpClient, new HttpGet(uri)));
            List<Map<String, Object>> keys = (List<Map<String, Object>>) map.get("keys");
            for (Map<String, Object> key : keys) {
                result.put(deepGet(key, "alg") + ":" + deepGet(key, "kid"), key);
            }
            return result;
        } catch (IOException | HttpException ex) { throw new VerificationException("unable to fetch key from jwks", ex); }
    }

    @SuppressWarnings("serial")
    public static class VerificationException extends Exception {
        VerificationException(String message) { super(message); }

        VerificationException(String message, Throwable cause) { super(message, cause); }
    }
}