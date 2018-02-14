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

import java.io.IOException;
import java.util.List;
import java.util.Map;

import static io.polyglotted.esjwt.impl.CommonUtil.deepGet;
import static io.polyglotted.esjwt.impl.CommonUtil.parseJson;
import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Locale.ENGLISH;
import static org.apache.commons.codec.binary.Base64.decodeBase64;

@Accessors(fluent = true)
public final class JsonWebToken {
    private final Map<String, Object> header;
    private final Map<String, Object> payload;
    private final byte[] contentBytes;
    private final byte[] signatureBytes;

    private JsonWebToken(Map<String, Object> header, Map<String, Object> payload, byte[] contentBytes, byte[] signatureBytes) {
        this.header = header; this.payload = payload; this.contentBytes = contentBytes; this.signatureBytes = signatureBytes;
    }

    public static JsonWebToken parse(String token) throws IOException {
        String[] parts = token.split("\\.");
        if (parts.length != 3) { throw new IllegalArgumentException("invalid token parts"); }
        return new JsonWebToken(parseJson(decodeBase64(parts[0])), parseJson(decodeBase64(parts[1])),
            String.format(ENGLISH, "%s.%s", parts[0], parts[1]).getBytes(UTF_8), decodeBase64(parts[2]));
    }

    public String keyCode() { return deepGet(header, "alg") + ":" + deepGet(header, "kid"); }

    public byte[] contentBytes() { return this.contentBytes; }

    public byte[] signatureBytes() { return this.signatureBytes; }

    public String issuer() { return deepGet(payload, "iss"); }

    public String subject() { return deepGet(payload, "sub"); }

    public List<String> audience() { return deepGet(payload, "aud"); }

    public Long expiresAt() { return deepGet(payload, "exp"); }

    public Long notBefore() { return deepGet(payload, "nbf"); }

    public Long issuedAt() { return deepGet(payload, "iat"); }

    public String jwtId() { return deepGet(payload, "jti"); }
}