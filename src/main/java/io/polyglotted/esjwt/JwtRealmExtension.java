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

import io.polyglotted.esjwt.realm.JwtRealm;
import io.polyglotted.esjwt.realm.JwtRealmFactory;
import org.elasticsearch.common.collect.MapBuilder;
import org.elasticsearch.watcher.ResourceWatcherService;
import org.elasticsearch.xpack.core.extensions.XPackExtension;
import org.elasticsearch.xpack.core.security.authc.AuthenticationFailureHandler;
import org.elasticsearch.xpack.core.security.authc.DefaultAuthenticationFailureHandler;
import org.elasticsearch.xpack.core.security.authc.Realm;

import java.util.Arrays;
import java.util.Collection;
import java.util.Map;

/**
 * The extension class that serves as the integration point between Elasticsearch, X-Pack, and any JWT provider
 */
public class JwtRealmExtension extends XPackExtension {

    @Override public String name() { return JwtRealm.TYPE; }

    @Override public String description() { return "Okta Realm Extension"; }

    /**
     * Returns a collection of header names that will be used by this extension. This is necessary to ensure the headers are copied from
     * the incoming request and made available to the realm.
     */
    @Override public Collection<String> getRestHeaders() { return Arrays.asList(JwtRealm.AUTH_HEADER); }

    /**
     * Returns a map of the custom realms provided by this extension. The first parameter is the string representation of the realm type;
     * this is the value that is specified when declaring a realm in the settings. Note, the realm type cannot be one of the types
     * defined by X-Pack. In order to avoid a conflict, you may wish to use some prefix to your realm types.
     * <p>
     * The second parameter is an instance of the {@link Realm.Factory} implementation. This factory class will be used to create realms of
     * this type that are defined in the elasticsearch settings.
     */
    @Override
    public Map<String, Realm.Factory> getRealms(ResourceWatcherService resourceWatcherService) {
        return new MapBuilder<String, Realm.Factory>().put(JwtRealm.TYPE, new JwtRealmFactory()).immutableMap();
    }

    /**
     * Returns the defaul {@link org.elasticsearch.xpack.core.security.authc.DefaultAuthenticationFailureHandler}
     */
    @Override
    public AuthenticationFailureHandler getAuthenticationFailureHandler() { return new DefaultAuthenticationFailureHandler(); }
}