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

import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import com.google.protobuf.Timestamp;
import org.dependencytrack.cache.api.Cache;
import org.dependencytrack.pkgmetadata.resolution.api.PackageRepository;
import org.dependencytrack.pkgmetadata.resolution.api.RetryableResolutionException;
import org.dependencytrack.pkgmetadata.resolution.cache.proto.v1.CacheEntry;
import org.dependencytrack.support.net.TransientNetworkErrors;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.function.Supplier;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;

import static java.util.Objects.requireNonNull;

/// @since 5.0.0
public final class CachingHttpClient {

    private static final Logger LOGGER = LoggerFactory.getLogger(CachingHttpClient.class);

    public static final Duration DEFAULT_FRESHNESS_CAP = Duration.ofHours(12);
    public static final long DEFAULT_MAX_COMPRESSED_BYTES = 16L * 1024 * 1024;
    public static final long DEFAULT_MAX_DECODED_BYTES = 64L * 1024 * 1024;

    private final HttpClient httpClient;
    private final Cache cache;
    private final Duration freshnessCap;
    private final long maxCompressedBytes;
    private final long maxDecodedBytes;
    private final Clock clock;
    private final RateLimitGate rateLimitGate;

    public CachingHttpClient(HttpClient httpClient, Cache cache) {
        this(httpClient, cache, DEFAULT_FRESHNESS_CAP, DEFAULT_MAX_COMPRESSED_BYTES, DEFAULT_MAX_DECODED_BYTES);
    }

    public CachingHttpClient(HttpClient httpClient, Cache cache, Duration freshnessCap) {
        this(httpClient, cache, freshnessCap, DEFAULT_MAX_COMPRESSED_BYTES, DEFAULT_MAX_DECODED_BYTES);
    }

    public CachingHttpClient(
            HttpClient httpClient,
            Cache cache,
            Duration freshnessCap,
            long maxCompressedBytes,
            long maxDecodedBytes) {
        this(httpClient, cache, freshnessCap, maxCompressedBytes, maxDecodedBytes, Clock.systemUTC());
    }

    CachingHttpClient(HttpClient httpClient, Cache cache, Duration freshnessCap, Clock clock) {
        this(httpClient, cache, freshnessCap, DEFAULT_MAX_COMPRESSED_BYTES, DEFAULT_MAX_DECODED_BYTES, clock);
    }

    /// @param httpClient         The [HttpClient] to execute requests with.
    /// @param cache              The [Cache] to store responses in.
    /// @param freshnessCap       For how long cache entries are considered fresh.
    /// Entries outside this freshness window will be revalidated.
    /// @param maxCompressedBytes Maximum number of bytes that compressed repository
    /// responses are allowed to have. Responses exceeding this limit will be dropped.
    /// @param maxDecodedBytes    Maximum number of bytes that decoded / decompressed
    /// responses are allowed to have. Responses exceeding this limit will be dropped.
    /// @param clock              The [Clock] to use for rate limit gating.
    CachingHttpClient(
            HttpClient httpClient,
            Cache cache,
            Duration freshnessCap,
            long maxCompressedBytes,
            long maxDecodedBytes,
            Clock clock) {
        this.httpClient = requireNonNull(httpClient, "httpClient must not be null");
        this.cache = requireNonNull(cache, "cache must not be null");
        this.freshnessCap = requireNonNull(freshnessCap, "freshnessCap must not be null");
        if (freshnessCap.isNegative() || freshnessCap.isZero()) {
            throw new IllegalArgumentException("freshnessCap must be positive: " + freshnessCap);
        }
        if (maxCompressedBytes <= 0 || maxCompressedBytes > Integer.MAX_VALUE) {
            throw new IllegalArgumentException(
                    "maxCompressedBytes must be in (0, %d]: %d".formatted(Integer.MAX_VALUE, maxCompressedBytes));
        }
        if (maxDecodedBytes < maxCompressedBytes || maxDecodedBytes > Integer.MAX_VALUE) {
            throw new IllegalArgumentException(
                    "maxDecodedBytes must be in [%d, %d]: %d".formatted(
                            maxCompressedBytes, Integer.MAX_VALUE, maxDecodedBytes));
        }
        this.maxCompressedBytes = maxCompressedBytes;
        this.maxDecodedBytes = maxDecodedBytes;
        this.clock = requireNonNull(clock, "clock must not be null");
        this.rateLimitGate = new RateLimitGate(clock);
    }

    public byte @Nullable [] get(
            HttpRequest.Builder requestBuilder,
            @Nullable PackageRepository repository) throws InterruptedException {
        requireNonNull(requestBuilder, "requestBuilder must not be null");

        final HttpRequest.Builder requestBuilderCopy = requestBuilder.copy();
        requestBuilderCopy.setHeader("Accept-Encoding", "gzip");
        final URI uri = requestBuilderCopy.build().uri();
        final String cacheKey = CacheKeys.forRequest("GET", uri, repository);
        final CacheEntry entry = getFromCache(cacheKey);

        if (entry != null && isFresh(entry)) {
            return decodedBodyOf(entry);
        }

        final byte[] staleResponseBody =
                shortCircuitIfRateLimited(uri, entry, this::staleBody);
        if (staleResponseBody != null) {
            return staleResponseBody;
        }

        applyValidators(requestBuilderCopy, entry);

        return sendWithStaleFallback(uri, entry, this::staleBody, () -> {
            final HttpResponse<byte[]> response = httpClient.send(
                    requestBuilderCopy.build(),
                    _ -> new LimitedBodySubscriber(maxCompressedBytes));
            return handleGetResponse(response, entry, cacheKey);
        });
    }

    public @Nullable HttpHeaders head(
            HttpRequest.Builder requestBuilder,
            @Nullable PackageRepository repository,
            Predicate<String> headerFilter) throws InterruptedException {
        requireNonNull(requestBuilder, "requestBuilder must not be null");
        requireNonNull(headerFilter, "headerFilter must not be null");

        final HttpRequest.Builder requestBuilderCopy = requestBuilder.copy();
        final URI uri = requestBuilderCopy.build().uri();
        final String cacheKey = CacheKeys.forRequest("HEAD", uri, repository);
        final CacheEntry entry = getFromCache(cacheKey);

        if (entry != null && isFresh(entry)) {
            return isPositiveHeadEntry(entry) ? rebuildHeaders(entry) : null;
        }

        final HttpHeaders staleResponseHeaders =
                shortCircuitIfRateLimited(uri, entry, CachingHttpClient::staleHeaders);
        if (staleResponseHeaders != null) {
            return staleResponseHeaders;
        }

        applyValidators(requestBuilderCopy, entry);

        return sendWithStaleFallback(uri, entry, CachingHttpClient::staleHeaders, () -> {
            final HttpResponse<Void> response = httpClient.send(
                    requestBuilderCopy.build(),
                    HttpResponse.BodyHandlers.discarding());
            return handleHeadResponse(response, entry, cacheKey, headerFilter);
        });
    }

    @FunctionalInterface
    private interface NetworkCall<T> {
        @Nullable T execute() throws IOException, InterruptedException;
    }

    private <T> @Nullable T sendWithStaleFallback(
            URI uri,
            @Nullable CacheEntry entry,
            Function<CacheEntry, @Nullable T> staleExtractor,
            NetworkCall<T> call) throws InterruptedException {
        try {
            return call.execute();
        } catch (RetryableResolutionException e) {
            return fallbackOrRethrow(entry, staleExtractor, uri, e, () -> e);
        } catch (IOException e) {
            return fallbackOrRethrow(
                    entry,
                    staleExtractor,
                    uri,
                    e,
                    TransientNetworkErrors.isTransient(e)
                            ? () -> new RetryableResolutionException(e)
                            : () -> new UncheckedIOException(e));
        }
    }

    private static <T> T fallbackOrRethrow(
            @Nullable CacheEntry entry,
            Function<CacheEntry, @Nullable T> staleExtractor,
            URI uri,
            Throwable cause,
            Supplier<? extends RuntimeException> rethrow) {
        if (entry != null) {
            final T stale = staleExtractor.apply(entry);
            if (stale != null) {
                LOGGER.debug("Revalidation failed for {}; serving stale cached value", uri, cause);
                return stale;
            }
        }

        throw rethrow.get();
    }

    private <T> @Nullable T shortCircuitIfRateLimited(
            URI uri,
            @Nullable CacheEntry entry,
            Function<CacheEntry, @Nullable T> staleExtractor) {
        final Instant rateLimitedUntil = rateLimitGate.checkRateLimited(uri);
        if (rateLimitedUntil == null) {
            return null;
        }

        if (entry != null) {
            final T stale = staleExtractor.apply(entry);
            if (stale != null) {
                LOGGER.debug(
                        "Host {} is rate-limited until {}; serving stale cached value",
                        uri.getAuthority(), rateLimitedUntil);
                return stale;
            }
        }

        final Duration remaining = Duration.between(clock.instant(), rateLimitedUntil);
        throw new RetryableResolutionException(
                "Host %s gated until %s".formatted(uri.getAuthority(), rateLimitedUntil),
                null,
                remaining.isPositive() ? remaining : null);
    }

    private static void applyValidators(HttpRequest.Builder requestBuilderCopy, @Nullable CacheEntry entry) {
        if (entry == null) {
            return;
        }

        // Per RFC 7232, prefer If-None-Match when both validators are available.
        if (entry.hasEtag()) {
            requestBuilderCopy.header("If-None-Match", entry.getEtag());
        } else if (entry.hasLastModified()) {
            requestBuilderCopy.header("If-Modified-Since", entry.getLastModified());
        }
    }

    private byte @Nullable [] handleGetResponse(
            HttpResponse<byte[]> response,
            @Nullable CacheEntry entry,
            String cacheKey) {
        final int status = response.statusCode();
        final var cacheControl = CacheControl.of(response);

        if (status == 304) {
            final CacheEntry matchedEntry = requireMatchingEntry(entry, cacheKey);

            if (cacheControl.noStore()) {
                cache.invalidateMany(Set.of(cacheKey));
            } else {
                final Long effectiveMaxAge = effectiveMaxAgeSeconds(cacheControl, matchedEntry);
                final CacheEntry.Builder refreshed = CacheEntry.newBuilder()
                        .setFreshUntil(freshUntilTs(cacheControl, matchedEntry));
                if (effectiveMaxAge != null) {
                    refreshed.setMaxAge(secondsAsDuration(effectiveMaxAge));
                }
                if (matchedEntry.hasBody()) {
                    refreshed.setBody(matchedEntry.getBody());
                }
                applyRefreshedValidators(refreshed, response, matchedEntry);
                cache.put(cacheKey, refreshed.build().toByteArray());
            }

            return decodedBodyOf(matchedEntry);
        }

        if (status == 200) {
            final boolean isGzip = isGzipEncoded(response.headers());
            final byte[] decodedBody = isGzip ? gunzipBounded(response.body()) : response.body();

            if (cacheControl.noStore()) {
                invalidateIfPresent(entry, cacheKey);
            } else {
                // Always cache gzipped, regardless of upstream's content negotiation.
                // Some responses can be large (e.g. some NPM packages have >10MiB worth of metadata).
                final byte[] cachedBody = isGzip ? response.body() : gzipCompress(response.body());
                final var freshEntryBuilder = CacheEntry.newBuilder()
                        .setFreshUntil(freshUntilTs(cacheControl, null))
                        .setBody(ByteString.copyFrom(cachedBody));
                if (cacheControl.maxAgeSeconds() != null) {
                    freshEntryBuilder.setMaxAge(secondsAsDuration(cacheControl.maxAgeSeconds()));
                }
                applyResponseValidators(freshEntryBuilder, response);
                cache.put(cacheKey, freshEntryBuilder.build().toByteArray());
            }

            return decodedBody;
        }

        if (status == 404 || status == 410) {
            cacheNegative(entry, cacheKey, cacheControl);
            return null;
        }

        return throwUnexpected(response);
    }

    private @Nullable HttpHeaders handleHeadResponse(
            HttpResponse<?> response,
            @Nullable CacheEntry entry,
            String cacheKey,
            Predicate<String> headerFilter) {
        final int status = response.statusCode();
        final var cacheControl = CacheControl.of(response);

        if (status == 304) {
            final CacheEntry matchedEntry = requireMatchingEntry(entry, cacheKey);

            if (cacheControl.noStore()) {
                cache.invalidateMany(Set.of(cacheKey));
                return rebuildHeaders(matchedEntry);
            }

            // Retain the cached headers map verbatim. RFC 7232 304 carries metadata only
            // (validators, Cache-Control). It does not re-send representation headers like
            // Content-Length, so overwriting would drop information.
            final Long effectiveMaxAge = effectiveMaxAgeSeconds(cacheControl, matchedEntry);
            final var refreshedEntryBuilder = CacheEntry.newBuilder()
                    .setFreshUntil(freshUntilTs(cacheControl, matchedEntry))
                    .putAllHeaders(matchedEntry.getHeadersMap());
            if (effectiveMaxAge != null) {
                refreshedEntryBuilder.setMaxAge(secondsAsDuration(effectiveMaxAge));
            }
            applyRefreshedValidators(refreshedEntryBuilder, response, matchedEntry);

            final CacheEntry refreshedEntry = refreshedEntryBuilder.build();
            cache.put(cacheKey, refreshedEntry.toByteArray());
            return rebuildHeaders(refreshedEntry);
        }

        if (status == 200) {
            if (cacheControl.noStore()) {
                invalidateIfPresent(entry, cacheKey);
                return response.headers();
            }

            final CacheEntry.Builder fresh = CacheEntry.newBuilder()
                    .setFreshUntil(freshUntilTs(cacheControl, null));
            if (cacheControl.maxAgeSeconds() != null) {
                fresh.setMaxAge(secondsAsDuration(cacheControl.maxAgeSeconds()));
            }
            applyResponseValidators(fresh, response);
            response.headers().map().forEach((name, values) -> {
                if (!values.isEmpty() && !isValidator(name) && headerFilter.test(name)) {
                    fresh.putHeaders(name.toLowerCase(Locale.ROOT), values.getFirst());
                }
            });

            final CacheEntry built = fresh.build();
            cache.put(cacheKey, built.toByteArray());
            return rebuildHeaders(built);
        }

        if (status == 404 || status == 410) {
            cacheNegative(entry, cacheKey, cacheControl);
            return null;
        }

        return throwUnexpected(response);
    }

    private void cacheNegative(
            @Nullable CacheEntry entry,
            String cacheKey,
            CacheControl cacheControl) {
        // Negative responses are cached so that repeated lookups for the same PURL
        // do not hammer the registry.
        if (cacheControl.noStore()) {
            invalidateIfPresent(entry, cacheKey);
            return;
        }

        final CacheEntry negativeEntry = CacheEntry.newBuilder()
                .setFreshUntil(freshUntilTs(cacheControl, entry))
                .build();
        cache.put(cacheKey, negativeEntry.toByteArray());
    }

    private void invalidateIfPresent(@Nullable CacheEntry entry, String cacheKey) {
        if (entry != null) {
            cache.invalidateMany(Set.of(cacheKey));
        }
    }

    private <T> T throwUnexpected(HttpResponse<?> response) {
        try {
            RetryableResolutionException.throwIfRetryableHttpError(response, clock);
        } catch (RetryableResolutionException e) {
            final Duration effectiveBackoff =
                    rateLimitGate.recordRateLimit(
                            response.request().uri(), e.retryAfter());
            throw new RetryableResolutionException(
                    e.getMessage(), e.getCause(), effectiveBackoff);
        }

        throw new UncheckedIOException(new IOException(
                "Unexpected status code %d for %s".formatted(response.statusCode(), response.request().uri())));
    }

    private static CacheEntry requireMatchingEntry(@Nullable CacheEntry entry, String cacheKey) {
        if (entry == null) {
            // Validators are only attached when a cached entry exists, so a 304 here
            // indicates a misbehaving upstream. Surface the inconsistency so the next
            // call refetches unconditionally.
            throw new UncheckedIOException(
                    new IOException("Received 304 without a matching cached entry for " + cacheKey));
        }

        return entry;
    }

    private static void applyResponseValidators(CacheEntry.Builder builder, HttpResponse<?> response) {
        response.headers().firstValue("ETag").ifPresent(builder::setEtag);
        response.headers().firstValue("Last-Modified").ifPresent(builder::setLastModified);
    }

    private static void applyRefreshedValidators(
            CacheEntry.Builder builder,
            HttpResponse<?> response,
            CacheEntry entry) {
        // Per RFC 7232, a 304 should include an updated validator if the resource has one.
        // Fall back to the previously cached validator when the response omits it.
        final String etag = response.headers().firstValue("ETag")
                .orElseGet(() -> entry.hasEtag() ? entry.getEtag() : null);
        final String lastModified = response.headers().firstValue("Last-Modified")
                .orElseGet(() -> entry.hasLastModified() ? entry.getLastModified() : null);
        if (etag != null) {
            builder.setEtag(etag);
        }
        if (lastModified != null) {
            builder.setLastModified(lastModified);
        }
    }

    private boolean isFresh(CacheEntry entry) {
        return clock.instant().isBefore(toInstant(entry.getFreshUntil()));
    }

    private static boolean isPositiveHeadEntry(CacheEntry entry) {
        return entry.hasEtag() || entry.hasLastModified() || !entry.getHeadersMap().isEmpty();
    }

    private static boolean isValidator(String headerName) {
        return "etag".equalsIgnoreCase(headerName) || "last-modified".equalsIgnoreCase(headerName);
    }

    private static HttpHeaders rebuildHeaders(CacheEntry cacheEntry) {
        final Map<String, List<String>> map = new HashMap<>();
        if (cacheEntry.hasEtag()) {
            map.put("ETag", List.of(cacheEntry.getEtag()));
        }
        if (cacheEntry.hasLastModified()) {
            map.put("Last-Modified", List.of(cacheEntry.getLastModified()));
        }
        for (final Map.Entry<String, String> headersEntry : cacheEntry.getHeadersMap().entrySet()) {
            map.put(headersEntry.getKey(), List.of(headersEntry.getValue()));
        }

        return HttpHeaders.of(map, (k, v) -> true);
    }

    private byte @Nullable [] staleBody(CacheEntry entry) {
        // RFC 9111 stale-if-error: only fall back when there is a body to serve.
        // Negative entries (404/410) carry no body and would mislead callers during an outage.
        // The entry's fresh_until is left as-is so the next call still attempts revalidation,
        // and the cache provider's eviction TTL is the absolute bound on staleness.
        try {
            return decodedBodyOf(entry);
        } catch (UncheckedIOException e) {
            LOGGER.debug("Failed to decode stale cached body, no fallback available", e);
            return null;
        }
    }

    private static @Nullable HttpHeaders staleHeaders(CacheEntry entry) {
        return isPositiveHeadEntry(entry) ? rebuildHeaders(entry) : null;
    }

    private Timestamp freshUntilTs(
            CacheControl cacheControl,
            @Nullable CacheEntry previousEntry) {
        return fromInstant(computeFreshUntil(cacheControl, previousEntry));
    }

    private Instant computeFreshUntil(
            CacheControl cacheControl,
            @Nullable CacheEntry previousEntry) {
        if (cacheControl.noCache()) {
            // Cache the body so that validators are available, but force the next call to
            // revalidate. RFC 7234 requires servers to perform validation before
            // returning the cached representation.
            return clock.instant();
        }

        final Long maxAgeSeconds = effectiveMaxAgeSeconds(cacheControl, previousEntry);
        final long capped = maxAgeSeconds != null
                ? Math.min(maxAgeSeconds, freshnessCap.getSeconds())
                : freshnessCap.getSeconds();
        return clock.instant().plusSeconds(capped);
    }

    private static @Nullable Long effectiveMaxAgeSeconds(
            CacheControl cacheControl,
            @Nullable CacheEntry previousEntry) {
        if (cacheControl.maxAgeSeconds() != null) {
            return cacheControl.maxAgeSeconds();
        }
        if (previousEntry != null && previousEntry.hasMaxAge()) {
            return previousEntry.getMaxAge().getSeconds();
        }
        return null;
    }

    private static com.google.protobuf.Duration secondsAsDuration(long seconds) {
        return com.google.protobuf.Duration.newBuilder().setSeconds(seconds).build();
    }

    private static Instant toInstant(Timestamp timestamp) {
        return Instant.ofEpochSecond(timestamp.getSeconds(), timestamp.getNanos());
    }

    private static Timestamp fromInstant(Instant instant) {
        return Timestamp.newBuilder()
                .setSeconds(instant.getEpochSecond())
                .setNanos(instant.getNano())
                .build();
    }

    private static boolean isGzipEncoded(HttpHeaders headers) {
        return headers.firstValue("Content-Encoding")
                .map(value -> "gzip".equalsIgnoreCase(value.trim()))
                .orElse(false);
    }

    private byte @Nullable [] decodedBodyOf(CacheEntry entry) {
        return entry.hasBody() ? gunzipBounded(entry.getBody().toByteArray()) : null;
    }

    private byte[] gunzipBounded(byte[] gzipped) {
        final int limit = (int) Math.min(Integer.MAX_VALUE, maxDecodedBytes + 1);
        try (var in = new GZIPInputStream(new ByteArrayInputStream(gzipped))) {
            final byte[] decoded = in.readNBytes(limit);
            if (decoded.length > maxDecodedBytes) {
                throw new IOException("Decoded body exceeds %d bytes".formatted(maxDecodedBytes));
            }
            return decoded;
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private static byte[] gzipCompress(byte[] body) {
        final var out = new ByteArrayOutputStream();
        try (var gzipOut = new GZIPOutputStream(out)) {
            gzipOut.write(body);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }

        return out.toByteArray();
    }

    private @Nullable CacheEntry getFromCache(String cacheKey) {
        final byte[] bytes = cache.get(cacheKey);
        if (bytes == null || bytes.length == 0) {
            return null;
        }

        try {
            final CacheEntry entry = CacheEntry.parseFrom(bytes);
            if (entry.hasBody() && !looksLikeGzip(entry.getBody())) {
                LOGGER.debug("Cached body is not gzip-encoded, evicting and treating as miss");
                cache.invalidateMany(Set.of(cacheKey));
                return null;
            }

            return entry;
        } catch (InvalidProtocolBufferException e) {
            LOGGER.debug("Failed to decode cached entry, evicting and treating as miss", e);
            cache.invalidateMany(Set.of(cacheKey));
            return null;
        }
    }

    private static boolean looksLikeGzip(ByteString body) {
        return body.size() >= 2
                && body.byteAt(0) == (byte) 0x1f
                && body.byteAt(1) == (byte) 0x8b;
    }

}
