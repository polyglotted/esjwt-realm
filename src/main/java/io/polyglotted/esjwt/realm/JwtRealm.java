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

import io.polyglotted.esjwt.impl.JsonWebToken;
import io.polyglotted.esjwt.impl.JwtValidator.ValidityException;
import io.polyglotted.esjwt.impl.JwtVerifier.VerificationException;
import org.apache.http.HttpHeaders;
import org.elasticsearch.action.ActionListener;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.xpack.core.security.authc.AuthenticationResult;
import org.elasticsearch.xpack.core.security.authc.AuthenticationToken;
import org.elasticsearch.xpack.core.security.authc.Realm;
import org.elasticsearch.xpack.core.security.authc.RealmConfig;
import org.elasticsearch.xpack.core.security.user.User;

import java.io.IOException;

import static io.polyglotted.esjwt.impl.JsonWebToken.parseJwt;
import static io.polyglotted.esjwt.impl.JwtValidator.validateJwt;
import static io.polyglotted.esjwt.impl.JwtVerifier.verifyRs256;
import static io.polyglotted.esjwt.realm.BearerToken.bearerToken;
import static java.time.Clock.systemUTC;

public class JwtRealm extends Realm {
    /* The type of the realm. This is defined as a static final variable to prevent typos */
    public static final String TYPE = "esjwt";
    private final String jwksUrl;

    /**
     * Constructor for the Realm. This constructor delegates to the super class to initialize the common aspects such
     * as the logger.
     *
     * @param config the configuration specific to this realm
     */
    JwtRealm(RealmConfig config) {
        super(TYPE, config);
        this.jwksUrl = config.settings().get("jwksUrl");
        logger.info("loaded x-pack plugin [esjwt]");
    }

    /**
     * Indicates whether this realm supports the given token. This realm only support {@link BearerToken} objects
     * for authentication
     *
     * @param token the token to test for support
     * @return true if the token is supported. false otherwise
     */
    @Override public boolean supports(AuthenticationToken token) { return token instanceof BearerToken; }

    /**
     * This method will extract a token from the given {@link RestRequest} if possible. This implementation of token
     * extraction looks for the specific header, the <code>X-Authorization</code> header
     *
     * @param context the {@link ThreadContext} that contains headers and transient objects for a request
     * @return the {@link AuthenticationToken} if possible to extract or <code>null</code>
     */
    @Override public AuthenticationToken token(ThreadContext context) {
        String authHeader = context.getHeader(HttpHeaders.AUTHORIZATION);
        return authHeader != null && authHeader.startsWith("Bearer ") ? bearerToken(authHeader.substring(7)) : null;
    }

    /**
     * Method that handles the actual authentication of the token. This method will only be called if the token is a
     * supported token. The method verifies that the <code>access_token</code> from the client is valid and on success,
     * a {@link User} will be returned as the argument to the {@code listener}'s {@link ActionListener#onResponse(Object)}
     * method. Else {@code null} is returned.
     *
     * @param authenticationToken the token to authenticate
     * @param listener            return authentication result by calling {@link ActionListener#onResponse(Object)}
     */
    @Override public void authenticate(AuthenticationToken authenticationToken, ActionListener<AuthenticationResult> listener) {
        try {
            JsonWebToken token = parseJwt(authenticationToken.credentials().toString());
            if (jwksUrl != null) { verifyRs256(jwksUrl, token); }

            User user = validateJwt(systemUTC(), token);
            listener.onResponse(AuthenticationResult.success(user));

        } catch (VerificationException | ValidityException ex) {
            listener.onResponse(AuthenticationResult.unsuccessful("failed to validate", ex));
        } catch (IOException ex) { listener.onFailure(ex); }
    }

    /**
     * This method looks for a user that is identified by the given String. No authentication is performed by this method.
     * If this realm does not support user lookup, then this method will not be called.
     *
     * @param username the identifier for the user
     * @param listener used to return lookup result
     */
    @Override public void lookupUser(String username, ActionListener<User> listener) { }
}