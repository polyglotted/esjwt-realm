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

import lombok.experimental.Accessors;
import org.elasticsearch.xpack.core.security.user.User;

import java.io.IOException;
import java.util.Map;
import java.util.regex.Pattern;

import static io.polyglotted.esjwt.impl.CommonUtil.asTime;
import static io.polyglotted.esjwt.impl.CommonUtil.deepGet;
import static io.polyglotted.esjwt.impl.CommonUtil.parseJson;
import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Locale.ENGLISH;
import static org.apache.commons.codec.binary.Base64.decodeBase64;

@Accessors(fluent = true)
public final class JsonWebToken {
    private static Pattern EMAIL_REGEX = Pattern.compile("(?:[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\\.[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]" +
        "+)*|\"(?:[\\x01-\\x08\\x0b\\x0c\\x0e-\\x1f\\x21\\x23-\\x5b\\x5d-\\x7f]|\\\\[\\x01-\\x09\\x0b\\x0c\\x0e-\\x7f])*\")@(?:(" +
        "?:[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?\\.)+[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?|\\[(?:(?:25[0-5]|2[0-4][0-9]|[0" +
        "1]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?|[A-Za-z0-9-]*[A-Za-z0-9]:(?:[\\x01-\\x08\\x0b\\x0c\\x0e-\\" +
        "x1f\\x21-\\x5a\\x53-\\x7f]|\\\\[\\x01-\\x09\\x0b\\x0c\\x0e-\\x7f])+)\\])");
    private final Map<String, Object> header;
    private final Map<String, Object> payload;
    private final byte[] contentBytes;
    private final byte[] signatureBytes;

    private JsonWebToken(Map<String, Object> header, Map<String, Object> payload, byte[] contentBytes, byte[] signatureBytes) {
        this.header = header; this.payload = payload; this.contentBytes = contentBytes; this.signatureBytes = signatureBytes;
    }

    public static JsonWebToken parseJwt(String token) throws IOException {
        String[] parts = token.split("\\.");
        if (parts.length != 3) { throw new IllegalArgumentException("invalid token parts"); }
        return new JsonWebToken(parseJson(decodeBase64(parts[0])), parseJson(decodeBase64(parts[1])),
            String.format(ENGLISH, "%s.%s", parts[0], parts[1]).getBytes(UTF_8), decodeBase64(parts[2]));
    }

    String keyCode() { return deepGet(header, "alg") + ":" + deepGet(header, "kid"); }

    byte[] contentBytes() { return this.contentBytes; }

    byte[] signatureBytes() { return this.signatureBytes; }

    Long expiresAt() { return asTime(payload, "exp"); }

    Long notBefore() { return asTime(payload, "nbf"); }

    Long issuedAt() { return asTime(payload, "iat"); }

    User buildUser() {
        return new User(userId(payload), new String[]{"jwt-user"}, null, email(payload), payload, true);
    }

    private static String userId(Map<String, Object> claims) { return (String) claims.getOrDefault("uid", claims.get("sub")); }

    private static String email(Map<String, Object> claims) {
        String email = (String) claims.getOrDefault("sub", ""); return EMAIL_REGEX.matcher(email).matches() ? email : null;
    }
}