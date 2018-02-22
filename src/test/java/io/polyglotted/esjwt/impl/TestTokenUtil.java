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

import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Signature;

import static io.polyglotted.esjwt.impl.JwtVerifier.RSA;
import static io.polyglotted.esjwt.impl.JwtVerifier.RSA_ALGO;
import static java.lang.System.currentTimeMillis;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.apache.commons.codec.binary.Base64.encodeBase64String;

public abstract class TestTokenUtil {
    private static final long TEN_MINS = 10 * 60 * 1000;

    public static String goodToken() { return testToken(currentTimeMillis(), currentTimeMillis() + TEN_MINS); }

    public static String badToken() { return testToken(currentTimeMillis(), currentTimeMillis() - 10_000); }

    private static String testToken(long iat, long exp) {
        String contentBytes = encodeBase64String(header().getBytes(UTF_8)) + "." +
            encodeBase64String(payload((int) (iat / 1000), (int) (exp / 1000)).getBytes(UTF_8));
        return contentBytes + "." + encodeBase64String(sign(contentBytes));
    }

    private static byte[] sign(String contentBytes) {
        try {
            KeyPairGenerator rsa = KeyPairGenerator.getInstance(RSA);
            rsa.initialize(1024, SecureRandom.getInstance("SHA1PRNG"));
            Signature s = Signature.getInstance(RSA_ALGO);
            s.initSign(rsa.generateKeyPair().getPrivate());
            s.update(contentBytes.getBytes(UTF_8));
            return s.sign();
        } catch (Exception ex) { throw new RuntimeException("failed to sign", ex); }
    }

    private static String header() { return "{\"kid\":\"_6La1ZuX1P80FpR2Q5eb0lDu5SNzmI5Rz6XFiBWE5bM\",\"alg\":\"RS256\"}"; }

    private static String payload(int issuedAt, int expiry) {
        return "{\"ver\":1,\"jti\":\"AT.E5kNYVzhMWHeA9KtVWmgTuhepSxBJhODPWD1YT1KieQ\"," +
            "\"iss\":\"https://dummy.dummy.com/oauth2/default\",\"aud\":\"api://default\"," +
            "\"iat\":" + issuedAt + ",\"exp\":" + expiry + ",\"uid\":\"abcdef1234ghij\"," +
            "\"cognito:groups\":[\"SUPERUSER\"],\"scp\":[\"openid\",\"profile\",\"email\"],\"sub\":\"tester@test.com\"}";
    }
}
