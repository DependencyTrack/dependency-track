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
package org.dependencytrack.pkgmetadata.resolution.cache;

import com.github.tomakehurst.wiremock.http.Fault;
import com.github.tomakehurst.wiremock.junit5.WireMockRuntimeInfo;
import com.github.tomakehurst.wiremock.junit5.WireMockTest;
import com.google.protobuf.ByteString;
import com.google.protobuf.Timestamp;
import io.smallrye.config.SmallRyeConfigBuilder;
import org.dependencytrack.cache.api.Cache;
import org.dependencytrack.cache.api.CacheManager;
import org.dependencytrack.cache.memory.MemoryCacheProvider;
import org.dependencytrack.pkgmetadata.resolution.api.RetryableResolutionException;
import org.dependencytrack.pkgmetadata.resolution.cache.proto.v1.CacheEntry;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.ByteArrayOutputStream;
import java.io.UncheckedIOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.concurrent.atomic.AtomicReference;
import java.util.zip.GZIPOutputStream;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.absent;
import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.head;
import static com.github.tomakehurst.wiremock.client.WireMock.headRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.stubFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static com.github.tomakehurst.wiremock.client.WireMock.verify;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

@WireMockTest
class CachingHttpClientTest {

    private static final String CACHE_NAME = "test-cache";
    private static final String PATH = "/resource";

    private CacheManager cacheManager;
    private Cache cache;
    private HttpClient httpClient;

    @BeforeEach
    void beforeEach() {
        final var cacheProvider = new MemoryCacheProvider(new SmallRyeConfigBuilder().build());
        cacheManager = cacheProvider.create();
        cache = cacheManager.getCache(CACHE_NAME);
        httpClient = HttpClient.newHttpClient();
    }

    @AfterEach
    void afterEach() throws Exception {
        if (cacheManager != null) {
            cacheManager.close();
        }
    }

    @Test
    void shouldGetAndCacheOnColdMiss(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubFor(get(urlPathEqualTo(PATH))
                .willReturn(aResponse().withStatus(200)
                        .withHeader("ETag", "\"abc\"")
                        .withHeader("Last-Modified", "Sat, 04 Nov 2023 12:00:00 GMT")
                        .withBody("hello")));

        final var cachingHttpClient = new CachingHttpClient(httpClient, cache, Duration.ofHours(1));
        final byte[] body = cachingHttpClient.get(requestBuilderFor(wmRuntimeInfo), null);

        assertThat(body).isEqualTo("hello".getBytes(StandardCharsets.UTF_8));
        verify(1, getRequestedFor(urlPathEqualTo(PATH)));
    }

    @Test
    void shouldReturnCachedBodyWithoutHttpWhenFresh(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubFor(get(urlPathEqualTo(PATH))
                .willReturn(aResponse().withStatus(200)
                        .withHeader("ETag", "\"abc\"")
                        .withBody("hello")));

        final var cachingHttpClient = new CachingHttpClient(httpClient, cache, Duration.ofHours(1));
        cachingHttpClient.get(requestBuilderFor(wmRuntimeInfo), null);
        final byte[] secondBody = cachingHttpClient.get(requestBuilderFor(wmRuntimeInfo), null);

        assertThat(secondBody).isEqualTo("hello".getBytes(StandardCharsets.UTF_8));
        verify(1, getRequestedFor(urlPathEqualTo(PATH)));
    }

    @ParameterizedTest
    @ValueSource(strings = {"\"abc\"", "W/\"weak-tag\""})
    void shouldRevalidateWith304AndEchoEtagVerbatim(String etag, WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubFor(get(urlPathEqualTo(PATH))
                .inScenario("revalidate")
                .whenScenarioStateIs("Started")
                .willReturn(aResponse().withStatus(200)
                        .withHeader("ETag", etag)
                        .withBody("hello"))
                .willSetStateTo("warmed"));
        stubFor(get(urlPathEqualTo(PATH))
                .inScenario("revalidate")
                .whenScenarioStateIs("warmed")
                .willReturn(aResponse().withStatus(304)));

        final var clock = new MutableClock();
        final var cachingHttpClient = new CachingHttpClient(httpClient, cache, Duration.ofMinutes(1), clock);
        cachingHttpClient.get(requestBuilderFor(wmRuntimeInfo), null);
        clock.advance(Duration.ofMinutes(2));
        final byte[] body = cachingHttpClient.get(requestBuilderFor(wmRuntimeInfo), null);

        assertThat(body).isEqualTo("hello".getBytes(StandardCharsets.UTF_8));
        verify(2, getRequestedFor(urlPathEqualTo(PATH)));
        verify(getRequestedFor(urlPathEqualTo(PATH))
                .withHeader("If-None-Match", equalTo(etag)));
    }

    @Test
    void shouldUseIfModifiedSinceWhenOnlyLastModifiedKnown(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubFor(get(urlPathEqualTo(PATH))
                .inScenario("if-mod-since")
                .whenScenarioStateIs("Started")
                .willReturn(aResponse().withStatus(200)
                        .withHeader("Last-Modified", "Sat, 04 Nov 2023 12:00:00 GMT")
                        .withBody("hello"))
                .willSetStateTo("warmed"));
        stubFor(get(urlPathEqualTo(PATH))
                .inScenario("if-mod-since")
                .whenScenarioStateIs("warmed")
                .willReturn(aResponse().withStatus(304)));

        final var clock = new MutableClock();
        final var cachingHttpClient = new CachingHttpClient(httpClient, cache, Duration.ofMinutes(1), clock);
        cachingHttpClient.get(requestBuilderFor(wmRuntimeInfo), null);
        clock.advance(Duration.ofMinutes(2));
        cachingHttpClient.get(requestBuilderFor(wmRuntimeInfo), null);

        verify(getRequestedFor(urlPathEqualTo(PATH))
                .withHeader("If-Modified-Since", equalTo("Sat, 04 Nov 2023 12:00:00 GMT"))
                .withHeader("If-None-Match", absent()));
    }

    @Test
    void shouldRefetchAndReplaceOn200WithNewETag(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubFor(get(urlPathEqualTo(PATH))
                .inScenario("refresh")
                .whenScenarioStateIs("Started")
                .willReturn(aResponse().withStatus(200)
                        .withHeader("ETag", "\"v1\"")
                        .withBody("first"))
                .willSetStateTo("changed"));
        stubFor(get(urlPathEqualTo(PATH))
                .inScenario("refresh")
                .whenScenarioStateIs("changed")
                .willReturn(aResponse().withStatus(200)
                        .withHeader("ETag", "\"v2\"")
                        .withBody("second")));

        final var clock = new MutableClock();
        final var cachingHttpClient = new CachingHttpClient(httpClient, cache, Duration.ofMinutes(1), clock);
        cachingHttpClient.get(requestBuilderFor(wmRuntimeInfo), null);
        clock.advance(Duration.ofMinutes(2));
        final byte[] body = cachingHttpClient.get(requestBuilderFor(wmRuntimeInfo), null);

        assertThat(body).isEqualTo("second".getBytes(StandardCharsets.UTF_8));
        verify(getRequestedFor(urlPathEqualTo(PATH))
                .withHeader("If-None-Match", equalTo("\"v1\"")));
    }

    @Test
    void shouldGetUnconditionallyWhenEntryHasNoValidators(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubFor(get(urlPathEqualTo(PATH))
                .willReturn(aResponse().withStatus(200).withBody("hello")));

        final var clock = new MutableClock();
        final var cachingHttpClient = new CachingHttpClient(httpClient, cache, Duration.ofMinutes(1), clock);
        cachingHttpClient.get(requestBuilderFor(wmRuntimeInfo), null);
        clock.advance(Duration.ofMinutes(2));
        cachingHttpClient.get(requestBuilderFor(wmRuntimeInfo), null);

        verify(2, getRequestedFor(urlPathEqualTo(PATH))
                .withHeader("If-None-Match", absent())
                .withHeader("If-Modified-Since", absent()));
    }

    @Test
    void shouldThrowRetryableExceptionOn503(WireMockRuntimeInfo wmRuntimeInfo) {
        stubFor(get(urlPathEqualTo(PATH))
                .willReturn(aResponse().withStatus(503)));

        final var cachingHttpClient = new CachingHttpClient(httpClient, cache, Duration.ofHours(1));
        assertThatExceptionOfType(RetryableResolutionException.class)
                .isThrownBy(() -> cachingHttpClient.get(requestBuilderFor(wmRuntimeInfo), null));
    }

    @ParameterizedTest
    @ValueSource(ints = {404, 410})
    void shouldCacheNegativeStatus(int status, WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubFor(get(urlPathEqualTo(PATH))
                .willReturn(aResponse().withStatus(status)));

        final var cachingHttpClient = new CachingHttpClient(httpClient, cache, Duration.ofHours(1));
        assertThat(cachingHttpClient.get(requestBuilderFor(wmRuntimeInfo), null)).isNull();
        assertThat(cachingHttpClient.get(requestBuilderFor(wmRuntimeInfo), null)).isNull();
        verify(1, getRequestedFor(urlPathEqualTo(PATH)));
    }

    @Test
    void shouldRefetchExpiredNegativeEntryWithoutValidators(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubFor(get(urlPathEqualTo(PATH))
                .willReturn(aResponse().withStatus(404)));

        final var clock = new MutableClock();
        final var cachingHttpClient = new CachingHttpClient(httpClient, cache, Duration.ofMinutes(1), clock);
        cachingHttpClient.get(requestBuilderFor(wmRuntimeInfo), null);
        clock.advance(Duration.ofMinutes(2));
        cachingHttpClient.get(requestBuilderFor(wmRuntimeInfo), null);

        verify(2, getRequestedFor(urlPathEqualTo(PATH))
                .withHeader("If-None-Match", absent())
                .withHeader("If-Modified-Since", absent()));
    }

    @Test
    void shouldReplaceCachedBodyWithNegativeEntryOn410(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubFor(get(urlPathEqualTo(PATH))
                .inScenario("gone")
                .whenScenarioStateIs("Started")
                .willReturn(aResponse().withStatus(200)
                        .withHeader("ETag", "\"v1\"")
                        .withBody("hello"))
                .willSetStateTo("gone"));
        stubFor(get(urlPathEqualTo(PATH))
                .inScenario("gone")
                .whenScenarioStateIs("gone")
                .willReturn(aResponse().withStatus(410)));

        final var clock = new MutableClock();
        final var cachingHttpClient = new CachingHttpClient(httpClient, cache, Duration.ofMinutes(1), clock);
        cachingHttpClient.get(requestBuilderFor(wmRuntimeInfo), null);
        clock.advance(Duration.ofMinutes(2));
        final byte[] afterGone = cachingHttpClient.get(requestBuilderFor(wmRuntimeInfo), null);
        // The negative entry is now fresh and replaces the prior body.
        final byte[] cachedNegative = cachingHttpClient.get(requestBuilderFor(wmRuntimeInfo), null);

        assertThat(afterGone).isNull();
        assertThat(cachedNegative).isNull();
        verify(2, getRequestedFor(urlPathEqualTo(PATH)));
    }

    @Test
    void shouldNotCacheNegativeWhenNoStoreDirectivePresent(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubFor(get(urlPathEqualTo(PATH))
                .willReturn(aResponse().withStatus(404)
                        .withHeader("Cache-Control", "no-store")));

        final var cachingHttpClient = new CachingHttpClient(httpClient, cache, Duration.ofHours(1));
        cachingHttpClient.get(requestBuilderFor(wmRuntimeInfo), null);
        cachingHttpClient.get(requestBuilderFor(wmRuntimeInfo), null);

        verify(2, getRequestedFor(urlPathEqualTo(PATH)));
    }

    @Test
    void shouldOverwriteCachedNegativeEntryWith200(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubFor(get(urlPathEqualTo(PATH))
                .inScenario("late-publish")
                .whenScenarioStateIs("Started")
                .willReturn(aResponse().withStatus(404))
                .willSetStateTo("published"));
        stubFor(get(urlPathEqualTo(PATH))
                .inScenario("late-publish")
                .whenScenarioStateIs("published")
                .willReturn(aResponse().withStatus(200)
                        .withHeader("ETag", "\"v1\"")
                        .withBody("hello")));

        final var clock = new MutableClock();
        final var cachingHttpClient = new CachingHttpClient(httpClient, cache, Duration.ofMinutes(1), clock);
        assertThat(cachingHttpClient.get(requestBuilderFor(wmRuntimeInfo), null)).isNull();
        clock.advance(Duration.ofMinutes(2));
        final byte[] body = cachingHttpClient.get(requestBuilderFor(wmRuntimeInfo), null);

        assertThat(body).isEqualTo("hello".getBytes(StandardCharsets.UTF_8));
        // After the negative entry is replaced, the next fresh call serves from cache.
        final byte[] cachedBody = cachingHttpClient.get(requestBuilderFor(wmRuntimeInfo), null);
        assertThat(cachedBody).isEqualTo("hello".getBytes(StandardCharsets.UTF_8));
        verify(2, getRequestedFor(urlPathEqualTo(PATH)));
    }

    @Test
    void shouldHonorUpstreamMaxAgeWhenShorterThanCap(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubFor(get(urlPathEqualTo(PATH))
                .willReturn(aResponse().withStatus(200)
                        .withHeader("ETag", "\"v1\"")
                        .withHeader("Cache-Control", "public, max-age=60")
                        .withBody("hello")));

        final var clock = new MutableClock();
        final var cachingHttpClient = new CachingHttpClient(httpClient, cache, Duration.ofHours(24), clock);
        cachingHttpClient.get(requestBuilderFor(wmRuntimeInfo), null);

        // Within the upstream-declared max-age: served from cache.
        clock.advance(Duration.ofSeconds(30));
        cachingHttpClient.get(requestBuilderFor(wmRuntimeInfo), null);
        verify(1, getRequestedFor(urlPathEqualTo(PATH)));

        // Past the upstream max-age but well within the cap: must revalidate.
        clock.advance(Duration.ofSeconds(60));
        cachingHttpClient.get(requestBuilderFor(wmRuntimeInfo), null);
        verify(2, getRequestedFor(urlPathEqualTo(PATH)));
        verify(getRequestedFor(urlPathEqualTo(PATH))
                .withHeader("If-None-Match", equalTo("\"v1\"")));
    }

    @Test
    void shouldCapUpstreamMaxAgeAtFreshnessCap(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubFor(get(urlPathEqualTo(PATH))
                .willReturn(aResponse().withStatus(200)
                        .withHeader("ETag", "\"v1\"")
                        .withHeader("Cache-Control", "max-age=86400")
                        .withBody("hello")));

        final var clock = new MutableClock();
        final var cachingHttpClient = new CachingHttpClient(httpClient, cache, Duration.ofMinutes(1), clock);
        cachingHttpClient.get(requestBuilderFor(wmRuntimeInfo), null);

        clock.advance(Duration.ofMinutes(2));
        cachingHttpClient.get(requestBuilderFor(wmRuntimeInfo), null);

        verify(2, getRequestedFor(urlPathEqualTo(PATH)));
    }

    @Test
    void shouldFallBackToCapWhenCacheControlAbsent(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubFor(get(urlPathEqualTo(PATH))
                .willReturn(aResponse().withStatus(200)
                        .withHeader("ETag", "\"v1\"")
                        .withBody("hello")));

        final var clock = new MutableClock();
        final var cachingHttpClient = new CachingHttpClient(httpClient, cache, Duration.ofHours(1), clock);
        cachingHttpClient.get(requestBuilderFor(wmRuntimeInfo), null);
        clock.advance(Duration.ofMinutes(30));
        cachingHttpClient.get(requestBuilderFor(wmRuntimeInfo), null);

        verify(1, getRequestedFor(urlPathEqualTo(PATH)));
    }

    @Test
    void shouldNotCacheResponsesWithNoStore(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubFor(get(urlPathEqualTo(PATH))
                .willReturn(aResponse().withStatus(200)
                        .withHeader("ETag", "\"v1\"")
                        .withHeader("Cache-Control", "no-store")
                        .withBody("hello")));

        final var cachingHttpClient = new CachingHttpClient(httpClient, cache, Duration.ofHours(1));
        final byte[] firstBody = cachingHttpClient.get(requestBuilderFor(wmRuntimeInfo), null);
        final byte[] secondBody = cachingHttpClient.get(requestBuilderFor(wmRuntimeInfo), null);

        assertThat(firstBody).isEqualTo("hello".getBytes(StandardCharsets.UTF_8));
        assertThat(secondBody).isEqualTo("hello".getBytes(StandardCharsets.UTF_8));
        verify(2, getRequestedFor(urlPathEqualTo(PATH))
                .withHeader("If-None-Match", absent()));
    }

    @Test
    void shouldRevalidateImmediatelyWhenNoCacheDirectivePresent(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubFor(get(urlPathEqualTo(PATH))
                .inScenario("no-cache")
                .whenScenarioStateIs("Started")
                .willReturn(aResponse().withStatus(200)
                        .withHeader("ETag", "\"v1\"")
                        .withHeader("Cache-Control", "no-cache")
                        .withBody("hello"))
                .willSetStateTo("warmed"));
        stubFor(get(urlPathEqualTo(PATH))
                .inScenario("no-cache")
                .whenScenarioStateIs("warmed")
                .willReturn(aResponse().withStatus(304)));

        final var cachingHttpClient = new CachingHttpClient(httpClient, cache, Duration.ofHours(1));
        cachingHttpClient.get(requestBuilderFor(wmRuntimeInfo), null);

        // Without advancing the clock, the next call must still revalidate.
        final byte[] secondBody = cachingHttpClient.get(requestBuilderFor(wmRuntimeInfo), null);

        assertThat(secondBody).isEqualTo("hello".getBytes(StandardCharsets.UTF_8));
        verify(getRequestedFor(urlPathEqualTo(PATH))
                .withHeader("If-None-Match", equalTo("\"v1\"")));
    }

    @Test
    void shouldHonorUpdatedCacheControlOn304(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubFor(get(urlPathEqualTo(PATH))
                .inScenario("refresh-cc")
                .whenScenarioStateIs("Started")
                .willReturn(aResponse().withStatus(200)
                        .withHeader("ETag", "\"v1\"")
                        .withHeader("Cache-Control", "max-age=60")
                        .withBody("hello"))
                .willSetStateTo("revalidated"));
        stubFor(get(urlPathEqualTo(PATH))
                .inScenario("refresh-cc")
                .whenScenarioStateIs("revalidated")
                .willReturn(aResponse().withStatus(304)
                        .withHeader("Cache-Control", "max-age=600")));

        final var clock = new MutableClock();
        final var cachingHttpClient = new CachingHttpClient(httpClient, cache, Duration.ofHours(1), clock);
        cachingHttpClient.get(requestBuilderFor(wmRuntimeInfo), null);

        clock.advance(Duration.ofMinutes(2));
        cachingHttpClient.get(requestBuilderFor(wmRuntimeInfo), null);

        // The 304 raised max-age to 600s, so a request 2 minutes later should be served from cache.
        clock.advance(Duration.ofMinutes(2));
        cachingHttpClient.get(requestBuilderFor(wmRuntimeInfo), null);

        verify(2, getRequestedFor(urlPathEqualTo(PATH)));
    }

    @Test
    void shouldPreservePreviousMaxAgeOn304WithoutCacheControl(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubFor(get(urlPathEqualTo(PATH))
                .inScenario("retain-cc")
                .whenScenarioStateIs("Started")
                .willReturn(aResponse().withStatus(200)
                        .withHeader("ETag", "\"v1\"")
                        .withHeader("Cache-Control", "max-age=60")
                        .withBody("hello"))
                .willSetStateTo("revalidated"));
        stubFor(get(urlPathEqualTo(PATH))
                .inScenario("retain-cc")
                .whenScenarioStateIs("revalidated")
                .willReturn(aResponse().withStatus(304)));

        final var clock = new MutableClock();
        final var cachingHttpClient = new CachingHttpClient(httpClient, cache, Duration.ofHours(1), clock);
        cachingHttpClient.get(requestBuilderFor(wmRuntimeInfo), null);

        // Past the upstream max-age: triggers revalidation.
        // The 304 omits Cache-Control, so freshness must be recomputed
        // from the previously cached max-age (60s), not extended to the full freshnessCap.
        clock.advance(Duration.ofMinutes(2));
        cachingHttpClient.get(requestBuilderFor(wmRuntimeInfo), null);

        // 30s after the 304 the entry is still within the carried-over 60s max-age.
        clock.advance(Duration.ofSeconds(30));
        cachingHttpClient.get(requestBuilderFor(wmRuntimeInfo), null);
        verify(2, getRequestedFor(urlPathEqualTo(PATH)));

        // 90s after the 304 the entry is stale again and must revalidate.
        clock.advance(Duration.ofSeconds(60));
        cachingHttpClient.get(requestBuilderFor(wmRuntimeInfo), null);
        verify(3, getRequestedFor(urlPathEqualTo(PATH)));
    }

    @Test
    void shouldRejectInvalidConstructorArguments() {
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> new CachingHttpClient(httpClient, cache, Duration.ZERO));
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> new CachingHttpClient(httpClient, cache, Duration.ofSeconds(-1)));
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> new CachingHttpClient(httpClient, cache, Duration.ofHours(1), 0, 0));
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> new CachingHttpClient(httpClient, cache, Duration.ofHours(1), -1, -1));
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> new CachingHttpClient(
                        httpClient, cache, Duration.ofHours(1), (long) Integer.MAX_VALUE + 1, (long) Integer.MAX_VALUE + 1));
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> new CachingHttpClient(httpClient, cache, Duration.ofHours(1), 1024, 512));
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> new CachingHttpClient(
                        httpClient, cache, Duration.ofHours(1), 1024, (long) Integer.MAX_VALUE + 1));
    }

    @Test
    void shouldThrowWhenResponseBodyExceedsMaxCompressedBytes(WireMockRuntimeInfo wmRuntimeInfo) {
        final byte[] payload = new byte[2048];
        stubFor(get(urlPathEqualTo(PATH))
                .willReturn(aResponse().withStatus(200)
                        .withHeader("ETag", "\"big\"")
                        .withBody(payload)));

        final var cachingHttpClient = new CachingHttpClient(httpClient, cache, Duration.ofHours(1), 1024, 1024);

        assertThatExceptionOfType(UncheckedIOException.class)
                .isThrownBy(() -> cachingHttpClient.get(requestBuilderFor(wmRuntimeInfo), null));

        assertThatExceptionOfType(UncheckedIOException.class)
                .isThrownBy(() -> cachingHttpClient.get(requestBuilderFor(wmRuntimeInfo), null));
        verify(2, getRequestedFor(urlPathEqualTo(PATH))
                .withHeader("If-None-Match", absent()));
    }

    @Test
    void shouldThrowWhenUpstreamReturns304WithoutMatchingEntry(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubFor(get(urlPathEqualTo(PATH))
                .inScenario("304-without-match")
                .whenScenarioStateIs("Started")
                .willReturn(aResponse().withStatus(304))
                .willSetStateTo("recovered"));
        stubFor(get(urlPathEqualTo(PATH))
                .inScenario("304-without-match")
                .whenScenarioStateIs("recovered")
                .willReturn(aResponse().withStatus(200).withBody("hello")));

        final var cachingHttpClient = new CachingHttpClient(httpClient, cache, Duration.ofHours(1));

        assertThatExceptionOfType(UncheckedIOException.class)
                .isThrownBy(() -> cachingHttpClient.get(requestBuilderFor(wmRuntimeInfo), null));

        final byte[] body = cachingHttpClient.get(requestBuilderFor(wmRuntimeInfo), null);
        assertThat(body).isEqualTo("hello".getBytes(StandardCharsets.UTF_8));
        verify(getRequestedFor(urlPathEqualTo(PATH))
                .withHeader("If-None-Match", absent())
                .withHeader("If-Modified-Since", absent()));
    }

    @ParameterizedTest(name = "[{index}] {0}")
    @CsvSource({
            "io-error, -1, 0",
            "503,      503, 0",
            "429,      429, 30",
    })
    void shouldServeStaleBodyOnRevalidationFailure(
            String label, int failureStatus, int retryAfterSeconds, WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubFor(get(urlPathEqualTo(PATH))
                .inScenario(label)
                .whenScenarioStateIs("Started")
                .willReturn(aResponse().withStatus(200)
                        .withHeader("ETag", "\"v1\"")
                        .withBody("hello"))
                .willSetStateTo("broken"));

        final var failureResponse = failureStatus < 0
                ? aResponse().withFault(Fault.CONNECTION_RESET_BY_PEER)
                : retryAfterSeconds > 0
                  ? aResponse().withStatus(failureStatus)
                .withHeader("Retry-After", String.valueOf(retryAfterSeconds))
                  : aResponse().withStatus(failureStatus);
        stubFor(get(urlPathEqualTo(PATH))
                .inScenario(label)
                .whenScenarioStateIs("broken")
                .willReturn(failureResponse));

        final var clock = new MutableClock();
        final var cachingHttpClient = new CachingHttpClient(httpClient, cache, Duration.ofMinutes(1), clock);
        cachingHttpClient.get(requestBuilderFor(wmRuntimeInfo), null);
        clock.advance(Duration.ofMinutes(2));

        final byte[] body = cachingHttpClient.get(requestBuilderFor(wmRuntimeInfo), null);

        assertThat(body).isEqualTo("hello".getBytes(StandardCharsets.UTF_8));
        verify(2, getRequestedFor(urlPathEqualTo(PATH)));
    }

    @Test
    void shouldServeStaleBodyOnTimeoutWhenEntryExists(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubFor(get(urlPathEqualTo(PATH))
                .inScenario("stale-on-timeout")
                .whenScenarioStateIs("Started")
                .willReturn(aResponse().withStatus(200)
                        .withHeader("ETag", "\"v1\"")
                        .withBody("hello"))
                .willSetStateTo("slow"));
        stubFor(get(urlPathEqualTo(PATH))
                .inScenario("stale-on-timeout")
                .whenScenarioStateIs("slow")
                .willReturn(aResponse().withStatus(200).withFixedDelay(2_000).withBody("late")));

        final var clock = new MutableClock();
        final var cachingHttpClient = new CachingHttpClient(httpClient, cache, Duration.ofMinutes(1), clock);
        cachingHttpClient.get(requestBuilderFor(wmRuntimeInfo), null);
        clock.advance(Duration.ofMinutes(2));

        final byte[] body = cachingHttpClient.get(
                HttpRequest.newBuilder()
                        .uri(URI.create(wmRuntimeInfo.getHttpBaseUrl() + PATH))
                        .timeout(Duration.ofMillis(250))
                        .GET(),
                null);

        assertThat(body).isEqualTo("hello".getBytes(StandardCharsets.UTF_8));
    }

    @Test
    void shouldRethrowIoExceptionWhenNoCachedEntry(WireMockRuntimeInfo wmRuntimeInfo) {
        stubFor(get(urlPathEqualTo(PATH))
                .willReturn(aResponse().withFault(Fault.CONNECTION_RESET_BY_PEER)));

        final var cachingHttpClient = new CachingHttpClient(httpClient, cache, Duration.ofHours(1));

        assertThatExceptionOfType(UncheckedIOException.class)
                .isThrownBy(() -> cachingHttpClient.get(requestBuilderFor(wmRuntimeInfo), null));
    }

    @Test
    void shouldRethrowRetryableExceptionWhenCachedEntryHasNoBody(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubFor(get(urlPathEqualTo(PATH))
                .inScenario("negative-then-503")
                .whenScenarioStateIs("Started")
                .willReturn(aResponse().withStatus(404))
                .willSetStateTo("down"));
        stubFor(get(urlPathEqualTo(PATH))
                .inScenario("negative-then-503")
                .whenScenarioStateIs("down")
                .willReturn(aResponse().withStatus(503)));

        final var clock = new MutableClock();
        final var cachingHttpClient = new CachingHttpClient(httpClient, cache, Duration.ofMinutes(1), clock);
        assertThat(cachingHttpClient.get(requestBuilderFor(wmRuntimeInfo), null)).isNull();
        clock.advance(Duration.ofMinutes(2));

        assertThatExceptionOfType(RetryableResolutionException.class)
                .isThrownBy(() -> cachingHttpClient.get(requestBuilderFor(wmRuntimeInfo), null));
    }

    @Test
    void shouldNotRefreshFreshnessOnStaleFallback(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubFor(get(urlPathEqualTo(PATH))
                .inScenario("stale-then-recover")
                .whenScenarioStateIs("Started")
                .willReturn(aResponse().withStatus(200)
                        .withHeader("ETag", "\"v1\"")
                        .withBody("hello"))
                .willSetStateTo("down"));
        stubFor(get(urlPathEqualTo(PATH))
                .inScenario("stale-then-recover")
                .whenScenarioStateIs("down")
                .willReturn(aResponse().withStatus(503))
                .willSetStateTo("recovered"));
        stubFor(get(urlPathEqualTo(PATH))
                .inScenario("stale-then-recover")
                .whenScenarioStateIs("recovered")
                .willReturn(aResponse().withStatus(304)));

        final var clock = new MutableClock();
        final var cachingHttpClient = new CachingHttpClient(httpClient, cache, Duration.ofMinutes(1), clock);
        cachingHttpClient.get(requestBuilderFor(wmRuntimeInfo), null);
        clock.advance(Duration.ofMinutes(2));

        // First stale call falls back to cached body. fresh_until must remain in the past.
        cachingHttpClient.get(requestBuilderFor(wmRuntimeInfo), null);

        // Advance past the rate-limit gate that the 503 just engaged (default 30s backoff),
        // so the next call is not short-circuited.
        clock.advance(Duration.ofSeconds(31));

        // Second call must still revalidate via If-None-Match, thus proving
        // the entry's freshness deadline was not refreshed by the prior stale fallback.
        final byte[] body = cachingHttpClient.get(requestBuilderFor(wmRuntimeInfo), null);

        assertThat(body).isEqualTo("hello".getBytes(StandardCharsets.UTF_8));
        verify(3, getRequestedFor(urlPathEqualTo(PATH)));
        verify(2, getRequestedFor(urlPathEqualTo(PATH))
                .withHeader("If-None-Match", equalTo("\"v1\"")));
    }

    @Test
    void shouldHeadAndCacheValidatorsAndFilteredHeaders(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubFor(head(urlPathEqualTo(PATH))
                .willReturn(aResponse().withStatus(200)
                        .withHeader("ETag", "\"v1\"")
                        .withHeader("Last-Modified", "Sat, 04 Nov 2023 12:00:00 GMT")
                        .withHeader("Content-Length", "1234")
                        .withHeader("Server", "nginx")));

        final var cachingHttpClient = new CachingHttpClient(httpClient, cache, Duration.ofHours(1));
        final HttpHeaders headers = cachingHttpClient.head(
                headRequestBuilderFor(wmRuntimeInfo), null, "content-length"::equalsIgnoreCase);

        assertThat(headers).isNotNull();
        assertThat(headers.firstValue("ETag")).hasValue("\"v1\"");
        assertThat(headers.firstValue("Last-Modified")).hasValue("Sat, 04 Nov 2023 12:00:00 GMT");
        assertThat(headers.firstValue("Content-Length")).hasValue("1234");
        assertThat(headers.firstValue("Server")).isEmpty();

        // Second call within freshness must be served from cache.
        final HttpHeaders cached = cachingHttpClient.head(
                headRequestBuilderFor(wmRuntimeInfo), null, "content-length"::equalsIgnoreCase);

        assertThat(cached.firstValue("ETag")).hasValue("\"v1\"");
        assertThat(cached.firstValue("Last-Modified")).hasValue("Sat, 04 Nov 2023 12:00:00 GMT");
        assertThat(cached.firstValue("Content-Length")).hasValue("1234");
        verify(1, headRequestedFor(urlPathEqualTo(PATH)));
    }

    @Test
    void shouldHeadReturnEtagAndLastModifiedEvenWhenPredicateRejectsThem(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubFor(head(urlPathEqualTo(PATH))
                .willReturn(aResponse().withStatus(200)
                        .withHeader("ETag", "\"v1\"")
                        .withHeader("Last-Modified", "Sat, 04 Nov 2023 12:00:00 GMT")));

        final var cachingHttpClient = new CachingHttpClient(httpClient, cache, Duration.ofHours(1));
        final HttpHeaders headers = cachingHttpClient.head(
                headRequestBuilderFor(wmRuntimeInfo), null, name -> false);

        assertThat(headers.firstValue("ETag")).hasValue("\"v1\"");
        assertThat(headers.firstValue("Last-Modified")).hasValue("Sat, 04 Nov 2023 12:00:00 GMT");
    }

    @Test
    void shouldHeadRevalidateWith304AndKeepCachedHeaders(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubFor(head(urlPathEqualTo(PATH))
                .inScenario("head-revalidate")
                .whenScenarioStateIs("Started")
                .willReturn(aResponse().withStatus(200)
                        .withHeader("ETag", "\"v1\"")
                        .withHeader("Content-Length", "42"))
                .willSetStateTo("warmed"));
        stubFor(head(urlPathEqualTo(PATH))
                .inScenario("head-revalidate")
                .whenScenarioStateIs("warmed")
                .willReturn(aResponse().withStatus(304)));

        final var clock = new MutableClock();
        final var cachingHttpClient = new CachingHttpClient(httpClient, cache, Duration.ofMinutes(1), clock);
        cachingHttpClient.head(headRequestBuilderFor(wmRuntimeInfo), null, "content-length"::equalsIgnoreCase);
        clock.advance(Duration.ofMinutes(2));
        final HttpHeaders headers = cachingHttpClient.head(
                headRequestBuilderFor(wmRuntimeInfo), null, "content-length"::equalsIgnoreCase);

        assertThat(headers.firstValue("ETag")).hasValue("\"v1\"");
        assertThat(headers.firstValue("Content-Length")).hasValue("42");
        verify(2, headRequestedFor(urlPathEqualTo(PATH)));
        verify(headRequestedFor(urlPathEqualTo(PATH))
                .withHeader("If-None-Match", equalTo("\"v1\"")));
    }

    @Test
    void shouldHeadCache404(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubFor(head(urlPathEqualTo(PATH))
                .willReturn(aResponse().withStatus(404)));

        final var cachingHttpClient = new CachingHttpClient(httpClient, cache, Duration.ofHours(1));
        assertThat(cachingHttpClient.head(headRequestBuilderFor(wmRuntimeInfo), null, name -> false)).isNull();
        assertThat(cachingHttpClient.head(headRequestBuilderFor(wmRuntimeInfo), null, name -> false)).isNull();

        verify(1, headRequestedFor(urlPathEqualTo(PATH)));
    }

    @Test
    void shouldHeadServeStaleHeadersOnRetryableError(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubFor(head(urlPathEqualTo(PATH))
                .inScenario("head-stale")
                .whenScenarioStateIs("Started")
                .willReturn(aResponse().withStatus(200)
                        .withHeader("ETag", "\"v1\"")
                        .withHeader("Content-Length", "42"))
                .willSetStateTo("down"));
        stubFor(head(urlPathEqualTo(PATH))
                .inScenario("head-stale")
                .whenScenarioStateIs("down")
                .willReturn(aResponse().withStatus(503)));

        final var clock = new MutableClock();
        final var cachingHttpClient = new CachingHttpClient(httpClient, cache, Duration.ofMinutes(1), clock);
        cachingHttpClient.head(headRequestBuilderFor(wmRuntimeInfo), null, "content-length"::equalsIgnoreCase);
        clock.advance(Duration.ofMinutes(2));

        final HttpHeaders stale = cachingHttpClient.head(
                headRequestBuilderFor(wmRuntimeInfo), null, "content-length"::equalsIgnoreCase);

        assertThat(stale.firstValue("ETag")).hasValue("\"v1\"");
        assertThat(stale.firstValue("Content-Length")).hasValue("42");
    }

    @Test
    void shouldHeadThrowOn304WithoutCachedEntry(WireMockRuntimeInfo wmRuntimeInfo) {
        stubFor(head(urlPathEqualTo(PATH))
                .willReturn(aResponse().withStatus(304)));

        final var cachingHttpClient = new CachingHttpClient(httpClient, cache, Duration.ofHours(1));
        assertThatExceptionOfType(UncheckedIOException.class)
                .isThrownBy(() -> cachingHttpClient.head(
                        headRequestBuilderFor(wmRuntimeInfo), null, name -> false));
    }

    @Test
    void shouldHeadAndGetUseDistinctCacheKeysForSameUri(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubFor(get(urlPathEqualTo(PATH))
                .willReturn(aResponse().withStatus(200)
                        .withHeader("ETag", "\"get\"")
                        .withBody("hello")));
        stubFor(head(urlPathEqualTo(PATH))
                .willReturn(aResponse().withStatus(200)
                        .withHeader("ETag", "\"head\"")
                        .withHeader("Content-Length", "5")));

        final var cachingHttpClient = new CachingHttpClient(httpClient, cache, Duration.ofHours(1));
        cachingHttpClient.get(requestBuilderFor(wmRuntimeInfo), null);
        final HttpHeaders headers = cachingHttpClient.head(
                headRequestBuilderFor(wmRuntimeInfo), null, "content-length"::equalsIgnoreCase);

        assertThat(headers.firstValue("ETag")).hasValue("\"head\"");
        verify(1, getRequestedFor(urlPathEqualTo(PATH)));
        verify(1, headRequestedFor(urlPathEqualTo(PATH)));
    }

    @Test
    void shouldSendAcceptEncodingGzipOnEveryRequest(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubFor(get(urlPathEqualTo(PATH))
                .willReturn(aResponse().withStatus(200).withBody("hello")));

        final var cachingHttpClient = new CachingHttpClient(httpClient, cache, Duration.ofHours(1));
        cachingHttpClient.get(requestBuilderFor(wmRuntimeInfo), null);

        verify(getRequestedFor(urlPathEqualTo(PATH))
                .withHeader("Accept-Encoding", equalTo("gzip")));
    }

    @Test
    void shouldOverrideCallerSuppliedAcceptEncoding(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubFor(get(urlPathEqualTo(PATH))
                .willReturn(aResponse().withStatus(200).withBody("hello")));

        final var cachingHttpClient = new CachingHttpClient(httpClient, cache, Duration.ofHours(1));
        cachingHttpClient.get(
                HttpRequest.newBuilder()
                        .uri(URI.create(wmRuntimeInfo.getHttpBaseUrl() + PATH))
                        .timeout(Duration.ofSeconds(5))
                        .header("Accept-Encoding", "identity")
                        .GET(),
                null);

        verify(getRequestedFor(urlPathEqualTo(PATH))
                .withHeader("Accept-Encoding", equalTo("gzip")));
    }

    @Test
    void shouldServeDecodedBodyOn304AfterGzipped200(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        final byte[] gzipped = gzip("hello".getBytes(StandardCharsets.UTF_8));
        stubFor(get(urlPathEqualTo(PATH))
                .inScenario("gzip-revalidate")
                .whenScenarioStateIs("Started")
                .willReturn(aResponse().withStatus(200)
                        .withHeader("Content-Encoding", "gzip")
                        .withHeader("ETag", "\"v1\"")
                        .withBody(gzipped))
                .willSetStateTo("warmed"));
        stubFor(get(urlPathEqualTo(PATH))
                .inScenario("gzip-revalidate")
                .whenScenarioStateIs("warmed")
                .willReturn(aResponse().withStatus(304)));

        final var clock = new MutableClock();
        final var cachingHttpClient = new CachingHttpClient(httpClient, cache, Duration.ofMinutes(1), clock);
        cachingHttpClient.get(requestBuilderFor(wmRuntimeInfo), null);
        clock.advance(Duration.ofMinutes(2));
        final byte[] body = cachingHttpClient.get(requestBuilderFor(wmRuntimeInfo), null);

        assertThat(body).isEqualTo("hello".getBytes(StandardCharsets.UTF_8));
    }

    @Test
    void shouldRejectGzipDecodedBodyExceedingMaxDecodedBytes(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        // 64 KiB of zeros compresses to ~80 bytes.
        // Well below the wire cap but above the decoded cap.
        final byte[] payload = new byte[64 * 1024];
        final byte[] gzipped = gzip(payload);
        stubFor(get(urlPathEqualTo(PATH))
                .willReturn(aResponse().withStatus(200)
                        .withHeader("Content-Encoding", "gzip")
                        .withBody(gzipped)));

        final var cachingHttpClient = new CachingHttpClient(httpClient, cache, Duration.ofHours(1), 8 * 1024, 8 * 1024);

        assertThatExceptionOfType(UncheckedIOException.class)
                .isThrownBy(() -> cachingHttpClient.get(requestBuilderFor(wmRuntimeInfo), null));
    }

    @Test
    void shouldAcceptGzipDecodedBodyWhenWithinDecodedCapButExceedingCompressedCap(
            WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        // 64 KiB of zeros compresses to ~80 bytes.
        // Passes the 1 KiB wire cap, and the 128 KiB decoded
        // cap accommodates the uncompressed payload.
        final byte[] payload = new byte[64 * 1024];
        final byte[] gzipped = gzip(payload);
        stubFor(get(urlPathEqualTo(PATH))
                .willReturn(aResponse().withStatus(200)
                        .withHeader("Content-Encoding", "gzip")
                        .withBody(gzipped)));

        final var cachingHttpClient = new CachingHttpClient(httpClient, cache, Duration.ofHours(1), 1024, 128 * 1024);
        final byte[] body = cachingHttpClient.get(requestBuilderFor(wmRuntimeInfo), null);

        assertThat(body).isEqualTo(payload);
    }

    @ParameterizedTest(name = "[{index}] Content-Encoding={0}")
    @CsvSource({
            "absent, plain",
            "br,     opaque",
    })
    void shouldPassThroughBodyWhenNotGzipEncoded(
            String encoding, String body, WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        final var stub = aResponse().withStatus(200).withBody(body);
        if (!"absent".equals(encoding)) {
            stub.withHeader("Content-Encoding", encoding);
        }
        stubFor(get(urlPathEqualTo(PATH)).willReturn(stub));

        final var cachingHttpClient = new CachingHttpClient(httpClient, cache, Duration.ofHours(1));
        final byte[] result = cachingHttpClient.get(requestBuilderFor(wmRuntimeInfo), null);

        assertThat(result).isEqualTo(body.getBytes(StandardCharsets.UTF_8));
    }

    @Test
    void shouldStoreCompressedBodyEvenWhenUpstreamServesPlain(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        final byte[] payload = new byte[4 * 1024];
        stubFor(get(urlPathEqualTo(PATH))
                .willReturn(aResponse().withStatus(200)
                        .withHeader("ETag", "\"v1\"")
                        .withBody(payload)));

        final var cachingHttpClient = new CachingHttpClient(httpClient, cache, Duration.ofHours(1));
        final byte[] body = cachingHttpClient.get(requestBuilderFor(wmRuntimeInfo), null);

        assertThat(body).isEqualTo(payload);

        final String cacheKey = "GET:" + wmRuntimeInfo.getHttpBaseUrl() + PATH;
        final byte[] cached = cache.get(cacheKey);
        assertThat(cached).isNotNull();
        assertThat(cached.length).isLessThan(payload.length);
    }

    @Test
    void shouldDecodeOnEveryFreshCacheHit(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        final byte[] gzipped = gzip("hello".getBytes(StandardCharsets.UTF_8));
        stubFor(get(urlPathEqualTo(PATH))
                .willReturn(aResponse().withStatus(200)
                        .withHeader("Content-Encoding", "gzip")
                        .withHeader("ETag", "\"v1\"")
                        .withBody(gzipped)));

        final var cachingHttpClient = new CachingHttpClient(httpClient, cache, Duration.ofHours(1));
        final byte[] expected = "hello".getBytes(StandardCharsets.UTF_8);
        assertThat(cachingHttpClient.get(requestBuilderFor(wmRuntimeInfo), null)).isEqualTo(expected);
        assertThat(cachingHttpClient.get(requestBuilderFor(wmRuntimeInfo), null)).isEqualTo(expected);
        assertThat(cachingHttpClient.get(requestBuilderFor(wmRuntimeInfo), null)).isEqualTo(expected);

        verify(1, getRequestedFor(urlPathEqualTo(PATH)));
    }

    @Test
    void shouldPreserveBodylessCachedEntryOn304(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        // Seed the cache with a stale, bodyless entry that nevertheless carries a validator.
        // Negative entries do not normally carry validators, so this is defensive against
        // legacy entries or a misbehaving upstream returning 304 unexpectedly.
        final var bodyless = CacheEntry.newBuilder()
                .setFreshUntil(Timestamp.newBuilder()
                        .setSeconds(Instant.now().minusSeconds(60).getEpochSecond()))
                .setEtag("\"v1\"")
                .build();
        final String cacheKey = "GET:" + wmRuntimeInfo.getHttpBaseUrl() + PATH;
        cache.put(cacheKey, bodyless.toByteArray());

        stubFor(get(urlPathEqualTo(PATH))
                .willReturn(aResponse().withStatus(304)));

        final var cachingHttpClient = new CachingHttpClient(httpClient, cache, Duration.ofHours(1));
        assertThat(cachingHttpClient.get(requestBuilderFor(wmRuntimeInfo), null)).isNull();

        // Refreshed entry must remain bodyless, not a cached empty 200.
        final CacheEntry refreshed = CacheEntry.parseFrom(cache.get(cacheKey));
        assertThat(refreshed.hasBody()).isFalse();
    }

    @Test
    void shouldTreatCorruptCachedBodyAsMiss(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        // Pre-populate the cache with a valid CacheEntry whose body is plain (non-gzip) bytes.
        final var legacy = CacheEntry.newBuilder()
                .setFreshUntil(Timestamp.newBuilder()
                        .setSeconds(Instant.now().plusSeconds(3600).getEpochSecond()))
                .setBody(ByteString.copyFromUtf8("not-gzipped"))
                .build();
        final String cacheKey = "GET:" + wmRuntimeInfo.getHttpBaseUrl() + PATH;
        cache.put(cacheKey, legacy.toByteArray());

        stubFor(get(urlPathEqualTo(PATH))
                .willReturn(aResponse().withStatus(200)
                        .withHeader("ETag", "\"v1\"")
                        .withBody("fresh")));

        final var cachingHttpClient = new CachingHttpClient(httpClient, cache, Duration.ofHours(1));
        final byte[] body = cachingHttpClient.get(requestBuilderFor(wmRuntimeInfo), null);

        assertThat(body).isEqualTo("fresh".getBytes(StandardCharsets.UTF_8));
        verify(1, getRequestedFor(urlPathEqualTo(PATH)));
    }

    @Test
    void shouldGateHostAfter429AndServeStale(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubFor(get(urlPathEqualTo(PATH))
                .inScenario("backoff")
                .whenScenarioStateIs("Started")
                .willReturn(aResponse().withStatus(200)
                        .withHeader("ETag", "\"v1\"")
                        .withBody("hello"))
                .willSetStateTo("limited"));
        stubFor(get(urlPathEqualTo(PATH))
                .inScenario("backoff")
                .whenScenarioStateIs("limited")
                .willReturn(aResponse().withStatus(429).withHeader("Retry-After", "60")));

        final var clock = new MutableClock();
        final var cachingHttpClient = new CachingHttpClient(httpClient, cache, Duration.ofMinutes(1), clock);
        cachingHttpClient.get(requestBuilderFor(wmRuntimeInfo), null);
        clock.advance(Duration.ofMinutes(2));

        final byte[] firstStale = cachingHttpClient.get(requestBuilderFor(wmRuntimeInfo), null);
        assertThat(firstStale).isEqualTo("hello".getBytes(StandardCharsets.UTF_8));
        verify(2, getRequestedFor(urlPathEqualTo(PATH)));

        final byte[] gatedStale = cachingHttpClient.get(requestBuilderFor(wmRuntimeInfo), null);
        assertThat(gatedStale).isEqualTo("hello".getBytes(StandardCharsets.UTF_8));
        verify(2, getRequestedFor(urlPathEqualTo(PATH)));
    }

    @Test
    void shouldGateHostAfter429AndThrowWhenNoStale(WireMockRuntimeInfo wmRuntimeInfo) {
        stubFor(get(urlPathEqualTo(PATH))
                .willReturn(aResponse().withStatus(429).withHeader("Retry-After", "60")));

        final var clock = new MutableClock();
        final var cachingHttpClient = new CachingHttpClient(httpClient, cache, Duration.ofHours(1), clock);
        assertThatExceptionOfType(RetryableResolutionException.class)
                .isThrownBy(() -> cachingHttpClient.get(requestBuilderFor(wmRuntimeInfo), null));

        assertThatExceptionOfType(RetryableResolutionException.class)
                .isThrownBy(() -> cachingHttpClient.get(requestBuilderFor(wmRuntimeInfo), null))
                .satisfies(e -> assertThat(e.retryAfter()).hasSeconds(60));
        verify(1, getRequestedFor(urlPathEqualTo(PATH)));
    }

    @Test
    void shouldReleaseHostGateAfterBackoffWindow(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubFor(get(urlPathEqualTo(PATH))
                .inScenario("backoff-release")
                .whenScenarioStateIs("Started")
                .willReturn(aResponse().withStatus(200)
                        .withHeader("ETag", "\"v1\"")
                        .withBody("hello"))
                .willSetStateTo("limited"));
        stubFor(get(urlPathEqualTo(PATH))
                .inScenario("backoff-release")
                .whenScenarioStateIs("limited")
                .willReturn(aResponse().withStatus(429).withHeader("Retry-After", "30"))
                .willSetStateTo("recovered"));
        stubFor(get(urlPathEqualTo(PATH))
                .inScenario("backoff-release")
                .whenScenarioStateIs("recovered")
                .willReturn(aResponse().withStatus(304)));

        final var clock = new MutableClock();
        final var cachingHttpClient = new CachingHttpClient(httpClient, cache, Duration.ofMinutes(1), clock);
        cachingHttpClient.get(requestBuilderFor(wmRuntimeInfo), null);
        clock.advance(Duration.ofMinutes(2));

        cachingHttpClient.get(requestBuilderFor(wmRuntimeInfo), null);
        verify(2, getRequestedFor(urlPathEqualTo(PATH)));

        clock.advance(Duration.ofSeconds(60));
        cachingHttpClient.get(requestBuilderFor(wmRuntimeInfo), null);
        verify(3, getRequestedFor(urlPathEqualTo(PATH)));
    }

    @Test
    void shouldGateHostAfter503AndServeStale(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubFor(get(urlPathEqualTo(PATH))
                .inScenario("backoff-5xx")
                .whenScenarioStateIs("Started")
                .willReturn(aResponse().withStatus(200)
                        .withHeader("ETag", "\"v1\"")
                        .withBody("hello"))
                .willSetStateTo("overloaded"));
        stubFor(get(urlPathEqualTo(PATH))
                .inScenario("backoff-5xx")
                .whenScenarioStateIs("overloaded")
                .willReturn(aResponse().withStatus(503)));

        final var clock = new MutableClock();
        final var cachingHttpClient = new CachingHttpClient(httpClient, cache, Duration.ofMinutes(1), clock);
        cachingHttpClient.get(requestBuilderFor(wmRuntimeInfo), null);
        clock.advance(Duration.ofMinutes(2));

        final byte[] firstStale = cachingHttpClient.get(requestBuilderFor(wmRuntimeInfo), null);
        assertThat(firstStale).isEqualTo("hello".getBytes(StandardCharsets.UTF_8));
        verify(2, getRequestedFor(urlPathEqualTo(PATH)));

        final byte[] gatedStale = cachingHttpClient.get(requestBuilderFor(wmRuntimeInfo), null);
        assertThat(gatedStale).isEqualTo("hello".getBytes(StandardCharsets.UTF_8));
        verify(2, getRequestedFor(urlPathEqualTo(PATH)));
    }

    private static byte[] gzip(byte[] input) throws Exception {
        final var out = new ByteArrayOutputStream();
        try (var gzipOut = new GZIPOutputStream(out)) {
            gzipOut.write(input);
        }

        return out.toByteArray();
    }

    private static HttpRequest.Builder headRequestBuilderFor(WireMockRuntimeInfo wmRuntimeInfo) {
        return HttpRequest.newBuilder()
                .uri(URI.create(wmRuntimeInfo.getHttpBaseUrl() + PATH))
                .timeout(Duration.ofSeconds(5))
                .method("HEAD", HttpRequest.BodyPublishers.noBody());
    }

    private static final class MutableClock extends Clock {

        private final AtomicReference<Instant> now = new AtomicReference<>(Instant.parse("2024-01-01T00:00:00Z"));

        @Override
        public Instant instant() {
            return now.get();
        }

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            throw new UnsupportedOperationException();
        }

        void advance(Duration delta) {
            now.updateAndGet(current -> current.plus(delta));
        }
    }

    private static HttpRequest.Builder requestBuilderFor(WireMockRuntimeInfo wmRuntimeInfo) {
        return HttpRequest.newBuilder()
                .uri(URI.create(wmRuntimeInfo.getHttpBaseUrl() + PATH))
                .timeout(Duration.ofSeconds(5))
                .GET();
    }

}
