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
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;

import static io.polyglotted.esjwt.impl.JwtVerifier.RSA;
import static io.polyglotted.esjwt.impl.JwtVerifier.RSA_ALGO;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.apache.commons.codec.binary.Base64.encodeBase64String;

public abstract class TestTokenUtil {

    public static String testToken(long time) {
        int expiry = (int) (time / 1000);
        String contentBytes = encodeBase64String(header().getBytes(UTF_8)) + "." +
            encodeBase64String(payload(expiry).getBytes(UTF_8));
        return contentBytes + "." + encodeBase64String(sign(contentBytes));
    }

    private static byte[] sign(String contentBytes) {
        try {
            String nVal = "hCXAc3p6ou6ZUFWA_Yg2QahFyo-Wbn9350abQwol_Npoc-sT1heaWgdeVjV9QcZ7-Mmtpfd989orKT8fi6T9Wb" +
                "RbLrgAqQnt1VNDS68588YNyFXoCNb7v2FXItVSQx0EUUk5W4yJAkXrHR84xkg_QTa3-4oevFya_gfShNjUhgUnKGTNI02G_" +
                "dhrfAKn6VwBIbwr5Gk2arwjckntSEF5BwgrHvxwy1EsZNUMD3wIko9eX-qjPFwpVIi3No1js_PO79l1wrBS6tYPZW6ZLEUX" +
                "-H159PvmrWyLb2-Io9ilGU8Fkq4VmLkYRPfEYcz3vfg3khdXFd2_rkCP7H--vuKWYQ";
            PublicKey publicKey = JwtVerifier.getPublicKey(RSA, nVal, "AQAB");

            KeyPairGenerator rsa = KeyPairGenerator.getInstance(RSA);
            rsa.initialize(1024, SecureRandom.getInstance("SHA1PRNG"));
            Signature s = Signature.getInstance(RSA_ALGO);
            s.initSign(rsa.generateKeyPair().getPrivate());
            s.update(contentBytes.getBytes(UTF_8));
            return s.sign();
        } catch (Exception ex) { throw new RuntimeException("failed to sign", ex); }
    }

    private static String header() { return "{\"kid\":\"_6La1ZuX1P80FpR2Q5eb0lDu5SNzmI5Rz6XFiBWE5bM\",\"alg\":\"RS256\"}"; }

    private static String payload(int expiry) {
        return "{\"ver\":1,\"jti\":\"AT.E5kNYVzhMWHeA9KtVWmgTuhepSxBJhODPWD1YT1KieQ\"," +
            "\"iss\":\"https://dummy.oktapreview.com/oauth2/default\",\"aud\":\"api://default\"," +
            "\"iat\":1518515038,\"exp\":" + expiry + ",\"uid\":\"abcdef1234ghij\"," +
            "\"scp\":[\"openid\",\"address\",\"phone\",\"profile\",\"email\"],\"sub\":\"tester@test.com\"}";
    }
}
