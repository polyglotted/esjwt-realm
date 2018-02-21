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
package io.polyglotted.esjwt.realm;

import org.elasticsearch.common.settings.SecureString;
import org.elasticsearch.xpack.core.security.authc.AuthenticationToken;

public class BearerToken implements AuthenticationToken {
    private final SecureString token;

    static BearerToken bearerToken(String value) { return new BearerToken(new SecureString(value.toCharArray())); }

    private BearerToken(SecureString token) { this.token = token; }

    @Override public String principal() { return "bearer"; }

    @Override public Object credentials() { return token; }

    @Override public void clearCredentials() { token.close(); }
}