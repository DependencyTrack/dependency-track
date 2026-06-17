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

import org.apache.hc.client5.http.protocol.HttpClientContext;
import org.apache.hc.core5.http.message.BasicHttpResponse;
import org.apache.hc.core5.util.TimeValue;
import org.assertj.core.data.Offset;
import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;

class GitHubHttpRequestRetryStrategyTest {

    @Test
    void shouldNotRetryOnResponseWithCode403() {
        final var httpResponse = new BasicHttpResponse(403);
        final var httpContext = HttpClientContext.create();

        final var retryStrategy = new GitHubHttpRequestRetryStrategy();
        final boolean shouldRetry = retryStrategy.retryRequest(httpResponse, 1, httpContext);
        assertThat(shouldRetry).isFalse();
    }

    @Test
    void shouldRetryOnResponseWithCode429() {
        final var httpResponse = new BasicHttpResponse(429);
        final var httpContext = HttpClientContext.create();

        final var retryStrategy = new GitHubHttpRequestRetryStrategy();
        final boolean shouldRetry = retryStrategy.retryRequest(httpResponse, 1, httpContext);
        assertThat(shouldRetry).isTrue();
    }

    @Test
    void shouldRetryOnResponseWithCode503() {
        final var httpResponse = new BasicHttpResponse(503);
        final var httpContext = HttpClientContext.create();

        final var retryStrategy = new GitHubHttpRequestRetryStrategy();
        final boolean shouldRetry = retryStrategy.retryRequest(httpResponse, 1, httpContext);
        assertThat(shouldRetry).isTrue();
    }

    @Test
    void shouldRetryUpToSixAttempts() {
        final var httpResponse = new BasicHttpResponse(503);
        final var httpContext = HttpClientContext.create();

        final var retryStrategy = new GitHubHttpRequestRetryStrategy();

        boolean shouldRetry = retryStrategy.retryRequest(httpResponse, 6, httpContext);
        assertThat(shouldRetry).isTrue();

        shouldRetry = retryStrategy.retryRequest(httpResponse, 7, httpContext);
        assertThat(shouldRetry).isFalse();
    }

    @Test
    void shouldRetryOnResponseWithCode403AndRetryAfterHeader() {
        final var httpResponse = new BasicHttpResponse(403);
        httpResponse.addHeader("retry-after", /* 1min */ 60);
        final var httpContext = HttpClientContext.create();

        final var retryStrategy = new GitHubHttpRequestRetryStrategy();
        final boolean shouldRetry = retryStrategy.retryRequest(httpResponse, 1, httpContext);
        assertThat(shouldRetry).isTrue();
    }

    @Test
    void shouldRetryOnResponseWithCode429AndRetryAfterHeader() {
        final var httpResponse = new BasicHttpResponse(429);
        httpResponse.addHeader("retry-after", /* 1min */ 60);
        final var httpContext = HttpClientContext.create();

        final var retryStrategy = new GitHubHttpRequestRetryStrategy();
        final boolean shouldRetry = retryStrategy.retryRequest(httpResponse, 1, httpContext);
        assertThat(shouldRetry).isTrue();
    }

    @Test
    void shouldNotRetryWhenRetryAfterExceedsMaxDelay() {
        final var httpResponse = new BasicHttpResponse(403);
        httpResponse.addHeader("retry-after", /* 3min */ 180);
        final var httpContext = HttpClientContext.create();

        final var retryStrategy = new GitHubHttpRequestRetryStrategy();
        boolean shouldRetry = retryStrategy.retryRequest(httpResponse, 1, httpContext);
        assertThat(shouldRetry).isTrue();

        httpResponse.setHeader("retry-after", /* 3min 1sec */ 181);
        shouldRetry = retryStrategy.retryRequest(httpResponse, 1, httpContext);
        assertThat(shouldRetry).isFalse();
    }

    @Test
    void shouldRetryOnResponseWithCode403AndRateLimitHeaders() {
        final var httpResponse = new BasicHttpResponse(403);
        httpResponse.addHeader("x-ratelimit-remaining", 6);
        httpResponse.addHeader("x-ratelimit-limit", 666);
        httpResponse.setHeader("x-ratelimit-reset", Instant.now().getEpochSecond());
        final var httpContext = HttpClientContext.create();

        final var retryStrategy = new GitHubHttpRequestRetryStrategy();
        final boolean shouldRetry = retryStrategy.retryRequest(httpResponse, 1, httpContext);
        assertThat(shouldRetry).isTrue();
    }

    @Test
    void shouldRetryOnResponseWithCode429AndRateLimitHeaders() {
        final var httpResponse = new BasicHttpResponse(429);
        httpResponse.addHeader("x-ratelimit-remaining", 6);
        httpResponse.addHeader("x-ratelimit-limit", 666);
        httpResponse.setHeader("x-ratelimit-reset", Instant.now().getEpochSecond());
        final var httpContext = HttpClientContext.create();

        final var retryStrategy = new GitHubHttpRequestRetryStrategy();
        final boolean shouldRetry = retryStrategy.retryRequest(httpResponse, 1, httpContext);
        assertThat(shouldRetry).isTrue();
    }

    @Test
    void shouldRetryWhenLimitResetIsShorterThanMaxDelay() {
        final var httpResponse = new BasicHttpResponse(429);
        httpResponse.addHeader("x-ratelimit-remaining", 0);
        httpResponse.addHeader("x-ratelimit-limit", 666);
        httpResponse.setHeader("x-ratelimit-reset", Instant.now().plusSeconds(/* 3min */ 180).getEpochSecond());
        final var httpContext = HttpClientContext.create();

        final var retryStrategy = new GitHubHttpRequestRetryStrategy();
        final boolean shouldRetry = retryStrategy.retryRequest(httpResponse, 1, httpContext);
        assertThat(shouldRetry).isTrue();
    }

    @Test
    void shouldNotRetryWhenLimitResetExceedsMaxDelay() {
        final var httpResponse = new BasicHttpResponse(429);
        httpResponse.addHeader("x-ratelimit-remaining", 0);
        httpResponse.addHeader("x-ratelimit-limit", 666);
        httpResponse.setHeader("x-ratelimit-reset", Instant.now().plusSeconds(/* 3min 1sec */ 181).getEpochSecond());
        final var httpContext = HttpClientContext.create();

        final var retryStrategy = new GitHubHttpRequestRetryStrategy();
        final boolean shouldRetry = retryStrategy.retryRequest(httpResponse, 1, httpContext);
        assertThat(shouldRetry).isFalse();
    }

    @Test
    void shouldUseRetryAfterHeaderForRetryDelay() {
        final var httpResponse = new BasicHttpResponse(429);
        httpResponse.addHeader("retry-after", /* 1min 6sec */ 66);
        final var httpContext = HttpClientContext.create();

        final var retryStrategy = new GitHubHttpRequestRetryStrategy();
        final TimeValue retryDelay = retryStrategy.getRetryInterval(httpResponse, 1, httpContext);
        assertThat(retryDelay.toSeconds()).isEqualTo(66);
    }

    @Test
    void shouldUseLimitResetHeaderForRetryDelay() {
        final var httpResponse = new BasicHttpResponse(429);
        httpResponse.addHeader("x-ratelimit-remaining", 0);
        httpResponse.addHeader("x-ratelimit-limit", 666);
        httpResponse.addHeader("x-ratelimit-reset", Instant.now().plusSeconds(66).getEpochSecond());
        final var httpContext = HttpClientContext.create();

        final var retryStrategy = new GitHubHttpRequestRetryStrategy();
        final TimeValue retryDelay = retryStrategy.getRetryInterval(httpResponse, 1, httpContext);
        assertThat(retryDelay.toSeconds()).isCloseTo(66, Offset.offset(1L));
    }

    @Test
    void shouldUseOneSecondAsDefaultRetryDelay() {
        final var httpResponse = new BasicHttpResponse(503);
        final var httpContext = HttpClientContext.create();

        final var retryStrategy = new GitHubHttpRequestRetryStrategy();
        final TimeValue retryDelay = retryStrategy.getRetryInterval(httpResponse, 1, httpContext);
        assertThat(retryDelay.toSeconds()).isEqualTo(1);
    }

}