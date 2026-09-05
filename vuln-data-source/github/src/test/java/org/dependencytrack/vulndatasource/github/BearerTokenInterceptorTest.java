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
package org.dependencytrack.vulndatasource.github;

import org.apache.hc.core5.http.HttpRequest;
import org.apache.hc.core5.http.message.BasicHttpRequest;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class BearerTokenInterceptorTest {

    @Test
    void shouldReplaceAuthorizationHeaderWithCurrentToken() throws Exception {
        final HttpRequest request = new BasicHttpRequest("GET", "/graphql");
        request.setHeader("Authorization", "token stale-value");

        new BearerTokenInterceptor(() -> "fresh-token").process(request, null, null);

        assertThat(request.getHeaders("Authorization")).hasSize(1);
        assertThat(request.getFirstHeader("Authorization").getValue()).isEqualTo("Bearer fresh-token");
    }
}
