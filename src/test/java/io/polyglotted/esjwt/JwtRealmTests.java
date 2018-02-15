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
package io.polyglotted.esjwt;

import io.polyglotted.esjwt.realm.BearerToken;
import io.polyglotted.esjwt.realm.JwtRealm;
import org.elasticsearch.action.ActionListener;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.env.Environment;
import org.elasticsearch.test.ESTestCase;
import org.elasticsearch.xpack.core.security.authc.RealmConfig;
import org.elasticsearch.xpack.core.security.user.User;

import static io.polyglotted.esjwt.impl.TestTokenUtil.testToken;
import static io.polyglotted.esjwt.realm.BearerToken.bearerToken;
import static java.lang.System.currentTimeMillis;
import static org.hamcrest.Matchers.arrayContaining;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;

public class JwtRealmTests extends ESTestCase {

    public void testAuthenticateValidUser() {
        BearerToken token = bearerToken(testToken(currentTimeMillis() + 10_000));
        createJwtRealm().authenticate(token, ActionListener.wrap(result -> {
            assertTrue(result.isAuthenticated());
            User user = result.getUser();
            assertThat(user, notNullValue());
            assertThat(user.roles(), arrayContaining("jwt-user"));
            assertThat(user.principal(), equalTo("abcdef1234ghij"));
            assertThat(user.email(), equalTo("tester@test.com"));
        }, e -> fail("Failed with exception: " + e.getMessage())));
    }

    public void testAuthenticateExpiredUser() {
        BearerToken token = bearerToken(testToken(currentTimeMillis() - 10_000));
        createJwtRealm().authenticate(token, ActionListener.wrap(result -> {
            assertFalse(result.isAuthenticated());
            assertThat(result.getUser(), nullValue());
        }, e -> fail("Failed with exception: " + e.getMessage())));
    }

    private static JwtRealm createJwtRealm() {
        Settings globalSettings = Settings.builder().put("path.home", createTempDir()).build();
        Settings realmSettings = Settings.builder()
            .put("type", JwtRealm.TYPE).build();
        return new JwtRealm(new RealmConfig("test", realmSettings, globalSettings,
            new Environment(globalSettings, createTempDir()), new ThreadContext(globalSettings)));
    }
}