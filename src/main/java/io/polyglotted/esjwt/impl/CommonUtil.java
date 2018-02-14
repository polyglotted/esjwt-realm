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

import org.apache.http.HttpException;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpRequestBase;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.util.EntityUtils;

import java.io.IOException;
import java.util.Map;

import static org.apache.http.HttpStatus.SC_MULTIPLE_CHOICES;
import static org.apache.http.HttpStatus.SC_OK;
import static org.apache.http.client.config.RequestConfig.custom;
import static org.elasticsearch.common.xcontent.NamedXContentRegistry.EMPTY;
import static org.elasticsearch.common.xcontent.XContentType.JSON;

@SuppressWarnings({"unchecked"})
public abstract class CommonUtil {

    static String readFrom(HttpClient httpClient, HttpRequestBase requestBase) throws IOException, HttpException {
        try {
            HttpResponse response = httpClient.execute(requestBase);
            int statusCode = response.getStatusLine().getStatusCode();
            checkState(statusCode >= SC_OK && statusCode < SC_MULTIPLE_CHOICES,
                response.getStatusLine().getReasonPhrase());
            return EntityUtils.toString(response.getEntity());
        } finally { requestBase.releaseConnection(); }
    }

    static CloseableHttpClient httpClient() {
        return HttpClientBuilder.create().setDefaultRequestConfig(custom().setConnectTimeout(10000)
            .setSocketTimeout(30000).build()).build();
    }

    private static void checkState(boolean status, String message) throws HttpException { if (!status) throw new HttpException(message); }

    static Map<String, Object> parseJson(String json) throws IOException { return JSON.xContent().createParser(EMPTY, json).map(); }

    static Map<String, Object> parseJson(byte[] bytes) throws IOException { return JSON.xContent().createParser(EMPTY, bytes).map(); }

    static <T> T deepGet(Map<String, Object> map, String property) {
        if (!property.contains(".")) return mapGet(map, property);

        String[] parts = property.split("\\.");
        Map<String, Object> child = map;
        for (int i = 0; i < parts.length - 1; i++) {
            child = mapGet(child, parts[i]);
            if (child == null) return null;
        }
        return (T) mapGet(child, parts[parts.length - 1]);
    }

    private static <T> T mapGet(Map<String, Object> map, String prop) { return (T) map.get(prop); }

    public static String join(String a, String b) {
        return notNullOrEmpty(a) ? (notNullOrEmpty(b) ? a + " " + b : a) : (notNullOrEmpty(b) ? b : "");
    }

    private static boolean notNullOrEmpty(String str) { return str != null && str.length() > 0; }
}