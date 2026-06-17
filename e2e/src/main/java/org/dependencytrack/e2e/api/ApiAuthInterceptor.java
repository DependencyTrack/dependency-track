/*
 * This file is part of Dependency-Track.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) OWASP Foundation. All Rights Reserved.
 */
package org.dependencytrack.e2e.api;

import feign.RequestInterceptor;
import feign.RequestTemplate;

public class ApiAuthInterceptor implements RequestInterceptor {

    private static String bearerToken;
    private static String apiKey;

    @Override
    public void apply(final RequestTemplate requestTemplate) {
        if (apiKey != null) {
            requestTemplate.header("X-Api-Key", apiKey);
        } else if (bearerToken != null) {
            requestTemplate.header("Authorization", "Bearer " + bearerToken);
        }
    }

    public static void setBearerToken(final String bearerToken) {
        ApiAuthInterceptor.bearerToken = bearerToken;
    }

    public static void setApiKey(final String apiKey) {
        ApiAuthInterceptor.apiKey = apiKey;
    }

    public static void reset() {
        ApiAuthInterceptor.bearerToken = null;
        ApiAuthInterceptor.apiKey = null;
    }

}
