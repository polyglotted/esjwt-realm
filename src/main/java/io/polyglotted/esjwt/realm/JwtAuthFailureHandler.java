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

import org.elasticsearch.ElasticsearchSecurityException;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.transport.TransportMessage;
import org.elasticsearch.xpack.core.security.authc.AuthenticationToken;
import org.elasticsearch.xpack.core.security.authc.DefaultAuthenticationFailureHandler;

/**
 * A custom implementation of a {@link org.elasticsearch.xpack.core.security.authc.AuthenticationFailureHandler}. The methods in this
 * class must return an {@link ElasticsearchSecurityException} with the appropriate status and headers for a client to
 * be able to handle an authentication failure. These methods can be called when there is a missing token, failure
 * to authenticate an extracted token, or when an exception occurs processing a request.
 * <p>
 * This class extends the {@link DefaultAuthenticationFailureHandler} provided by X-Pack and changes the <code>WWW-Authenticate</code>
 * header to return a JWT failure. The default return value is a 401 status with a Basic authentication challenge.
 */
public class JwtAuthFailureHandler extends DefaultAuthenticationFailureHandler {

    @Override
    public ElasticsearchSecurityException failedAuthentication(RestRequest request, AuthenticationToken token, ThreadContext context) {
        return buildJwtFailure(super.failedAuthentication(request, token, context));
    }

    @Override
    public ElasticsearchSecurityException failedAuthentication(TransportMessage message, AuthenticationToken token, String action,
                                                               ThreadContext context) {
        return buildJwtFailure(super.failedAuthentication(message, token, action, context));
    }

    @Override
    public ElasticsearchSecurityException missingToken(RestRequest request, ThreadContext context) {
        return buildJwtFailure(super.missingToken(request, context));
    }

    @Override
    public ElasticsearchSecurityException missingToken(TransportMessage message, String action, ThreadContext context) {
        return buildJwtFailure(super.missingToken(message, action, context));
    }

    @Override
    public ElasticsearchSecurityException exceptionProcessingRequest(RestRequest request, Exception e, ThreadContext context) {
        return buildJwtFailure(super.exceptionProcessingRequest(request, e, context));
    }

    @Override
    public ElasticsearchSecurityException exceptionProcessingRequest(TransportMessage message, String action, Exception e,
                                                                     ThreadContext context) {
        return buildJwtFailure(super.exceptionProcessingRequest(message, action, e, context));
    }

    @Override
    public ElasticsearchSecurityException authenticationRequired(String action, ThreadContext context) {
        return buildJwtFailure(super.authenticationRequired(action, context));
    }

    private static ElasticsearchSecurityException buildJwtFailure(ElasticsearchSecurityException se) {
        se.addHeader("WWW-Authenticate", "jwt-error"); return se;
    }
}
