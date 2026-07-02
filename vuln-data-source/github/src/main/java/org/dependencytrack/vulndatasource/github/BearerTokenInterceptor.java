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

import org.apache.hc.core5.http.EntityDetails;
import org.apache.hc.core5.http.HttpRequest;
import org.apache.hc.core5.http.HttpRequestInterceptor;
import org.apache.hc.core5.http.protocol.HttpContext;

/**
 * Stamps {@code Authorization: Bearer <token>} on every outgoing request, using
 * the current token from the {@link GitHubTokenProvider}. Any pre-existing
 * {@code Authorization} header is removed first so there is a single, self-refreshing
 * auth code path for both PAT and GitHub App modes.
 */
final class BearerTokenInterceptor implements HttpRequestInterceptor {

    private final GitHubTokenProvider tokenProvider;

    BearerTokenInterceptor(final GitHubTokenProvider tokenProvider) {
        this.tokenProvider = tokenProvider;
    }

    @Override
    public void process(final HttpRequest request, final EntityDetails entity, final HttpContext context) {
        request.removeHeaders("Authorization");
        request.setHeader("Authorization", "Bearer " + tokenProvider.currentToken());
    }

}
