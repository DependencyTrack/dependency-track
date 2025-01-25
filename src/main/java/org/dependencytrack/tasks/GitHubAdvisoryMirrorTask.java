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
package org.dependencytrack.tasks;

import alpine.common.logging.Logger;
import alpine.common.util.ProxyConfig;
import alpine.common.util.ProxyUtil;
import alpine.event.framework.Event;
import alpine.event.framework.LoggableSubscriber;
import alpine.model.ConfigProperty;
import alpine.notification.Notification;
import alpine.notification.NotificationLevel;
import io.github.jeremylong.openvulnerability.client.ghsa.GitHubSecurityAdvisoryClient;
import io.github.jeremylong.openvulnerability.client.ghsa.GitHubSecurityAdvisoryClientBuilder;
import io.github.jeremylong.openvulnerability.client.ghsa.SecurityAdvisory;
import org.apache.commons.lang3.StringUtils;
import org.apache.hc.client5.http.impl.DefaultHttpRequestRetryStrategy;
import org.apache.hc.client5.http.impl.async.HttpAsyncClientBuilder;
import org.apache.hc.client5.http.impl.async.HttpAsyncClients;
import org.apache.hc.client5.http.impl.routing.SystemDefaultRoutePlanner;
import org.apache.hc.core5.http.ConnectionClosedException;
import org.apache.hc.core5.http.Header;
import org.apache.hc.core5.http.HttpResponse;
import org.apache.hc.core5.http.protocol.HttpContext;
import org.apache.hc.core5.util.TimeValue;
import org.dependencytrack.common.AlpineHttpProxySelector;
import org.dependencytrack.common.ManagedHttpClientFactory;
import org.dependencytrack.event.GitHubAdvisoryMirrorEvent;
import org.dependencytrack.event.IndexEvent;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.VulnerabilityAlias;
import org.dependencytrack.model.VulnerableSoftware;
import org.dependencytrack.notification.NotificationConstants;
import org.dependencytrack.notification.NotificationGroup;
import org.dependencytrack.notification.NotificationScope;
import org.dependencytrack.parser.github.ModelConverter;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.persistence.listener.IndexingInstanceLifecycleListener;
import org.slf4j.MDC;

import javax.net.ssl.SSLException;
import java.io.InterruptedIOException;
import java.net.ConnectException;
import java.net.NoRouteToHostException;
import java.net.UnknownHostException;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.temporal.ChronoUnit;
import java.util.Collection;
import java.util.List;
import java.util.Optional;

import static io.github.jeremylong.openvulnerability.client.ghsa.GitHubSecurityAdvisoryClientBuilder.aGitHubSecurityAdvisoryClient;
import static org.datanucleus.PropertyNames.PROPERTY_PERSISTENCE_BY_REACHABILITY_AT_COMMIT;
import static org.dependencytrack.common.MdcKeys.MDC_VULN_ID;
import static org.dependencytrack.model.ConfigPropertyConstants.VULNERABILITY_SOURCE_GITHUB_ADVISORIES_ACCESS_TOKEN;
import static org.dependencytrack.model.ConfigPropertyConstants.VULNERABILITY_SOURCE_GITHUB_ADVISORIES_ALIAS_SYNC_ENABLED;
import static org.dependencytrack.model.ConfigPropertyConstants.VULNERABILITY_SOURCE_GITHUB_ADVISORIES_API_URL;
import static org.dependencytrack.model.ConfigPropertyConstants.VULNERABILITY_SOURCE_GITHUB_ADVISORIES_ENABLED;
import static org.dependencytrack.model.ConfigPropertyConstants.VULNERABILITY_SOURCE_GITHUB_ADVISORIES_LAST_MODIFIED_EPOCH_SECONDS;

public class GitHubAdvisoryMirrorTask implements LoggableSubscriber {

    private static final Logger LOGGER = Logger.getLogger(GitHubAdvisoryMirrorTask.class);

    private final ModelConverter modelConverter = new ModelConverter(LOGGER);
    private final boolean isEnabled;
    private final String apiUrl;
    private final String accessToken;
    private final boolean aliasSyncEnabled;
    private final long lastModifiedEpochSeconds;

    public GitHubAdvisoryMirrorTask() {
        try (final var qm = new QueryManager()) {
            isEnabled = qm.isEnabled(VULNERABILITY_SOURCE_GITHUB_ADVISORIES_ENABLED);
            if (!isEnabled) {
                apiUrl = null;
                accessToken = null;
                aliasSyncEnabled = false;
                lastModifiedEpochSeconds = 0;
                return;
            }

            final ConfigProperty apiUrlProperty = qm.getConfigProperty(
                    VULNERABILITY_SOURCE_GITHUB_ADVISORIES_API_URL.getGroupName(),
                    VULNERABILITY_SOURCE_GITHUB_ADVISORIES_API_URL.getPropertyName());
            final ConfigProperty accessTokenProperty = qm.getConfigProperty(
                    VULNERABILITY_SOURCE_GITHUB_ADVISORIES_ACCESS_TOKEN.getGroupName(),
                    VULNERABILITY_SOURCE_GITHUB_ADVISORIES_ACCESS_TOKEN.getPropertyName());
            final ConfigProperty lastModifiedProperty = qm.getConfigProperty(
                    VULNERABILITY_SOURCE_GITHUB_ADVISORIES_LAST_MODIFIED_EPOCH_SECONDS.getGroupName(),
                    VULNERABILITY_SOURCE_GITHUB_ADVISORIES_LAST_MODIFIED_EPOCH_SECONDS.getPropertyName());

            apiUrl = Optional.ofNullable(apiUrlProperty)
                    .map(ConfigProperty::getPropertyValue)
                    .map(StringUtils::trimToNull)
                    .orElseThrow(() -> new IllegalStateException("No API URL configured"));
            accessToken = Optional.ofNullable(accessTokenProperty)
                    .map(ConfigProperty::getPropertyValue)
                    .map(StringUtils::trimToNull)
                    // TODO: https://github.com/DependencyTrack/dependency-track/issues/3332
//                    .map(encryptedAccessToken -> {
//                        try {
//                            return DebugDataEncryption.decryptAsString(encryptedAccessToken);
//                        } catch (Exception ex) {
//                            throw new IllegalStateException("Failed to decrypt access token", ex);
//                        }
//                    })
                    .orElseThrow(() -> new IllegalStateException("No access token configured"));
            lastModifiedEpochSeconds = Optional.ofNullable(lastModifiedProperty)
                    .map(ConfigProperty::getPropertyValue)
                    .map(StringUtils::trimToNull)
                    .filter(StringUtils::isNumeric)
                    .map(Long::parseLong)
                    .orElse(0L);
            aliasSyncEnabled = qm.isEnabled(VULNERABILITY_SOURCE_GITHUB_ADVISORIES_ALIAS_SYNC_ENABLED);
        }
    }

    public void inform(final Event e) {
        if (!(e instanceof GitHubAdvisoryMirrorEvent) || !isEnabled) {
            return;
        }

        final long startTimeNs = System.nanoTime();
        int numMirrored = 0;
        Instant lastStatusLog = Instant.now();
        ZonedDateTime committedLastModified = null;

        try (final GitHubSecurityAdvisoryClient client = createApiClient(apiUrl, accessToken, lastModifiedEpochSeconds)) {
            while (client.hasNext()) {
                boolean shouldCommitSearchIndex = false;
                final Collection<SecurityAdvisory> advisories = client.next();
                for (final SecurityAdvisory advisory : advisories) {
                    try (var ignoredMdcVulnId = MDC.putCloseable(MDC_VULN_ID, advisory.getGhsaId())) {
                        final boolean wasCreatedOrUpdated = processAdvisory(advisory);
                        if (wasCreatedOrUpdated) {
                            shouldCommitSearchIndex = true;
                        }
                    }

                    final int currentNumMirrored = ++numMirrored;
                    if (lastStatusLog.plus(5, ChronoUnit.SECONDS).isBefore(Instant.now())) {
                        final int currentMirroredPercentage = (currentNumMirrored * 100) / client.getTotalAvailable();
                        LOGGER.info("Mirrored %d/%d GHSAs (%d%%); Last committed modification timestamp: %s".formatted(
                                currentNumMirrored, client.getTotalAvailable(), currentMirroredPercentage, committedLastModified));
                        lastStatusLog = Instant.now();
                    }
                }

                committedLastModified = maybeCommitLastModified(client.getLastUpdated());

                if (shouldCommitSearchIndex) {
                    Event.dispatch(new IndexEvent(IndexEvent.Action.COMMIT, Vulnerability.class));
                    Event.dispatch(new IndexEvent(IndexEvent.Action.COMMIT, VulnerableSoftware.class));
                }
            }

            if (numMirrored > 0) {
                LOGGER.info("""
                        Successfully mirrored %d GHSAs in %s \
                        (last committed modification timestamp: %s)""".formatted(
                        numMirrored, Duration.ofNanos(System.nanoTime() - startTimeNs), committedLastModified));
            } else {
                LOGGER.info("No modified GHSAs available; Mirror is already up-to-date");
            }
            Notification.dispatch(new Notification()
                    .scope(NotificationScope.SYSTEM)
                    .group(NotificationGroup.DATASOURCE_MIRRORING)
                    .title(NotificationConstants.Title.GITHUB_ADVISORY_MIRROR)
                    .content("Mirroring of GitHub Advisories completed successfully")
                    .level(NotificationLevel.INFORMATIONAL));
        } catch (Exception ex) {
            LOGGER.error("""
                    An unexpected error occurred after mirroring %d GHSAs in %s \
                    (last committed modification timestamp: %s)""".formatted(
                    numMirrored, Duration.ofNanos(System.nanoTime() - startTimeNs), committedLastModified), ex);
            Notification.dispatch(new Notification()
                    .scope(NotificationScope.SYSTEM)
                    .group(NotificationGroup.DATASOURCE_MIRRORING)
                    .title(NotificationConstants.Title.GITHUB_ADVISORY_MIRROR)
                    .content("An error occurred mirroring the contents of GitHub Advisories. Check log for details.")
                    .level(NotificationLevel.ERROR));
        }
    }

    boolean processAdvisory(final SecurityAdvisory advisory) {
        final Vulnerability vuln = modelConverter.convert(advisory);
        if (vuln == null) {
            return false;
        }

        final List<VulnerableSoftware> vsList = modelConverter.convert(advisory.getVulnerabilities());

        try (final var qm = new QueryManager().withL2CacheDisabled()) {
            qm.getPersistenceManager().setProperty(PROPERTY_PERSISTENCE_BY_REACHABILITY_AT_COMMIT, "false");
            qm.getPersistenceManager().addInstanceLifecycleListener(
                    new IndexingInstanceLifecycleListener(Event::dispatch),
                    Vulnerability.class,
                    VulnerableSoftware.class);

            final Vulnerability persistentVuln = qm.callInTransaction(() -> {
                final Vulnerability syncedVuln = qm.synchronizeVulnerability(vuln, false);
                if (syncedVuln == null) {
                    LOGGER.debug("Vulnerability was mirrored before and did not change");
                    return null;
                }

                if (aliasSyncEnabled && vuln.getAliases() != null && !vuln.getAliases().isEmpty()) {
                    for (final VulnerabilityAlias alias : vuln.getAliases()) {
                        qm.synchronizeVulnerabilityAlias(alias);
                    }
                }

                return syncedVuln;
            });

            if (persistentVuln != null) {
                qm.synchronizeVulnerableSoftware(persistentVuln, vsList, Vulnerability.Source.GITHUB);
                return true;
            }
        }

        return false;
    }

    private GitHubSecurityAdvisoryClient createApiClient(
            final String apiUrl,
            final String accessToken,
            final long lastModifiedEpochSeconds) {
        final ProxyConfig proxyConfig = ProxyUtil.getProxyConfig();
        final HttpAsyncClientBuilder httpClientBuilder = HttpAsyncClients.custom()
                .setRetryStrategy(new HttpRequestRetryStrategy())
                .setRoutePlanner(new SystemDefaultRoutePlanner(new AlpineHttpProxySelector(proxyConfig)))
                .useSystemProperties();

        final GitHubSecurityAdvisoryClientBuilder clientBuilder = aGitHubSecurityAdvisoryClient()
                .withHttpClientSupplier(httpClientBuilder::build)
                .withAdditionalUserAgent(ManagedHttpClientFactory.getUserAgent())
                .withEndpoint(apiUrl)
                .withApiKey(accessToken);
        if (lastModifiedEpochSeconds > 0) {
            final var lastModifiedDateTime = ZonedDateTime.ofInstant(
                    Instant.ofEpochSecond(lastModifiedEpochSeconds), ZoneOffset.UTC);
            clientBuilder.withUpdatedSinceFilter(lastModifiedDateTime);
            LOGGER.info("Mirroring GHSAs that were modified since %s".formatted(lastModifiedDateTime));
        } else {
            LOGGER.info("GHSAs were not incrementally mirrored before; Mirroring all GHSAs");
        }

        return clientBuilder.build();
    }

    static final class HttpRequestRetryStrategy extends DefaultHttpRequestRetryStrategy {

        private enum RateLimitStrategy {
            RETRY_AFTER,
            LIMIT_RESET
        }

        private record RateLimitInfo(
                RateLimitStrategy strategy,
                Duration retryAfter,
                Long remainingRequests,
                Long requestLimit,
                Instant requestLimitResetAt) {

            private static RateLimitInfo of(final HttpResponse response) {
                final Header retryAfterHeader = response.getFirstHeader("retry-after");
                if (retryAfterHeader != null) {
                    final long retryAfterSeconds = Long.parseLong(retryAfterHeader.getValue().trim());
                    return new RateLimitInfo(RateLimitStrategy.RETRY_AFTER, Duration.ofSeconds(retryAfterSeconds), null, null, null);
                }

                final Header remainingRequestsHeader = response.getFirstHeader("x-ratelimit-remaining");
                if (remainingRequestsHeader != null) {
                    final long remainingRequests = Long.parseLong(remainingRequestsHeader.getValue().trim());
                    final long requestLimit = Long.parseLong(response.getFirstHeader("x-ratelimit-limit").getValue().trim());
                    final long requestLimitResetEpochSeconds = Long.parseLong(response.getFirstHeader("x-ratelimit-reset").getValue().trim());
                    return new RateLimitInfo(RateLimitStrategy.LIMIT_RESET, null, remainingRequests, requestLimit, Instant.ofEpochSecond(requestLimitResetEpochSeconds));
                }

                return null;
            }

        }

        private final Duration maxRetryDelay = Duration.ofMinutes(3);

        HttpRequestRetryStrategy() {
            super(
                    /* maxRetries */ 6,
                    /* defaultRetryInterval */ TimeValue.ofSeconds(1L),
                    // Same as DefaultHttpRequestRetryStrategy.
                    /* retryableExceptions */ List.of(
                            ConnectException.class,
                            ConnectionClosedException.class,
                            InterruptedIOException.class,
                            NoRouteToHostException.class,
                            SSLException.class,
                            UnknownHostException.class),
                    // Same as DefaultHttpRequestRetryStrategy, with addition of 403,
                    // since GitHub might use that status to indicate rate limiting.
                    /* retryableCodes */ List.of(403, 429, 503));
        }

        @Override
        public boolean retryRequest(final HttpResponse response, final int execCount, final HttpContext context) {
            if (response.getCode() != 403 && response.getCode() != 429) {
                return super.retryRequest(response, execCount, context);
            }

            final var rateLimitInfo = RateLimitInfo.of(response);
            if (rateLimitInfo == null) {
                if (response.getCode() == 403) {
                    // Authorization failure. Do not retry.
                    return false;
                }

                return super.retryRequest(response, execCount, context);
            }

            return switch (rateLimitInfo.strategy()) {
                case RETRY_AFTER -> {
                    // Usually GitHub will request to wait for 1min. This may change though, and we can't risk
                    // blocking a worker thread unnecessarily for a long period of time.
                    if (rateLimitInfo.retryAfter().compareTo(maxRetryDelay) > 0) {
                        LOGGER.warn("""
                            Rate limiting detected; GitHub API indicates retries to be acceptable after %s, \
                            which exceeds the maximum retry duration of %s. \
                            Not performing any further retries.""".formatted(
                                rateLimitInfo.retryAfter(), maxRetryDelay));
                        yield false;
                    }

                    yield true;
                }
                case LIMIT_RESET -> {
                    if (rateLimitInfo.remainingRequests() > 0) {
                        // Still have requests budget remaining. Failure reason is not rate limiting.
                        yield super.retryRequest(response, execCount, context);
                    }

                    // The duration after which the limit is reset is not defined in GitHub's API docs.
                    // Need to safeguard ourselves from blocking the worker thread for too long.
                    final var untilResetDuration = Duration.between(Instant.now(), rateLimitInfo.requestLimitResetAt());
                    if (untilResetDuration.compareTo(maxRetryDelay) > 0) {
                        LOGGER.warn("""
                            Primary rate limit of %d requests exhausted. The rate limit will reset at %s (in %s), \
                            which exceeds the maximum retry duration of %s. Not performing any further retries.""".formatted(
                                rateLimitInfo.requestLimit(), rateLimitInfo.requestLimitResetAt(), untilResetDuration, maxRetryDelay));
                        yield false;
                    }

                    yield true;
                }
            };
        }

        @Override
        public TimeValue getRetryInterval(final HttpResponse response, final int execCount, final HttpContext context) {
            // When this is called, retryRequest was already invoked to determine whether
            // a retry should be performed. So we can skip the status code check here.

            final var rateLimitInfo = RateLimitInfo.of(response);
            if (rateLimitInfo == null) {
                return super.getRetryInterval(response, execCount, context);
            }

            return switch (rateLimitInfo.strategy()) {
                case RETRY_AFTER -> {
                    LOGGER.warn("""
                        Rate limiting detected; GitHub indicates retries to be acceptable after %s; \
                        Will wait and try again.""".formatted(rateLimitInfo.retryAfter()));
                    yield TimeValue.ofMilliseconds(rateLimitInfo.retryAfter().toMillis());
                }
                case LIMIT_RESET -> {
                    final var retryAfter = Duration.between(Instant.now(), rateLimitInfo.requestLimitResetAt());
                    LOGGER.warn("""
                        Primary rate limit of %d requests exhausted. Limit will reset at %s; \
                        Will wait for %s and try again.""".formatted(
                            rateLimitInfo.requestLimit(), rateLimitInfo.requestLimitResetAt(), retryAfter));
                    yield TimeValue.ofMilliseconds(retryAfter.toMillis());
                }
            };
        }

    }

    private static ZonedDateTime maybeCommitLastModified(final ZonedDateTime lastModifiedDateTime) {
        if (lastModifiedDateTime == null) {
            return null;
        }

        try (final var qm = new QueryManager()) {
            return qm.callInTransaction(() -> {
                final ConfigProperty property = qm.getConfigProperty(
                        VULNERABILITY_SOURCE_GITHUB_ADVISORIES_LAST_MODIFIED_EPOCH_SECONDS.getGroupName(),
                        VULNERABILITY_SOURCE_GITHUB_ADVISORIES_LAST_MODIFIED_EPOCH_SECONDS.getPropertyName());
                final var previous = property.getPropertyValue() != null
                        ? ZonedDateTime.ofInstant(Instant.ofEpochSecond(Long.parseLong(property.getPropertyValue())), ZoneOffset.UTC)
                        : ZonedDateTime.ofInstant(Instant.EPOCH, ZoneOffset.UTC);

                if (previous.isBefore(lastModifiedDateTime)) {
                    LOGGER.debug("Updating last captured modification date: %s -> %s".formatted(
                            previous, lastModifiedDateTime));
                    property.setPropertyValue(String.valueOf(lastModifiedDateTime.toEpochSecond()));
                    return lastModifiedDateTime;
                }

                return previous;
            });
        }
    }

}
