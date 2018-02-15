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

import org.elasticsearch.xpack.core.security.user.User;

import java.time.Clock;

import static io.polyglotted.esjwt.impl.JwtValidator.ValidityException.dateFail;
import static java.time.Instant.ofEpochMilli;
import static java.time.ZoneOffset.UTC;

public abstract class JwtValidator {

    public static User validateJwt(Clock clock, JsonWebToken token) throws ValidityException {
        validateBefore(clock, token.notBefore());
        validateBefore(clock, token.issuedAt());
        validateAfter(clock, token.expiresAt());
        return token.buildUser();
    }

    static void validateBefore(Clock clock, Long time) throws ValidityException {
        if (time != null) {
            if (time > (clock.millis() + 1000)) { throw dateFail("time occurs in the past ", time); }
        }
    }

    static void validateAfter(Clock clock, Long time) throws ValidityException {
        if (time != null) {
            if (time < (clock.millis() - 1000)) { throw dateFail("token has expired ", time.intValue()); }
        }
    }

    @SuppressWarnings("serial")
    public static class ValidityException extends Exception {
        ValidityException(String message) { super(message); }

        static ValidityException dateFail(String message, long time) {
            return new ValidityException(message + ofEpochMilli(time).atOffset(UTC).toLocalDateTime());
        }
    }
}