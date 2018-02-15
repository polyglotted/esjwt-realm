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

import io.polyglotted.esjwt.impl.JwtValidator.ValidityException;
import org.elasticsearch.test.ESTestCase;

import java.time.Clock;

import static io.polyglotted.esjwt.impl.JwtValidator.validateAfter;
import static io.polyglotted.esjwt.impl.JwtValidator.validateBefore;
import static java.time.Instant.ofEpochMilli;
import static java.time.ZoneOffset.UTC;

public class JwtValidatorTests extends ESTestCase {

    public void testDateBefore() throws Exception {
        Clock clock = Clock.fixed(ofEpochMilli(1518518638000L), UTC);
        validateBefore(clock, null);
        validateBefore(clock, 1518518632000L);
        validateBefore(clock, 1518518638000L);
        try {
            validateBefore(clock, 1518518642000L);
            fail("cannot come here");
        } catch (ValidityException e) {
            //success
        }
    }

    public void testDateAfter() throws Exception {
        Clock clock = Clock.fixed(ofEpochMilli(1518518638000L), UTC);
        validateAfter(clock, null);
        validateAfter(clock, 1518518642000L);
        validateAfter(clock, 1518518638000L);
        try {
            validateAfter(clock, 1518518632000L);
            fail("cannot come here");
        } catch (ValidityException e) {
            //success
        }
    }
}