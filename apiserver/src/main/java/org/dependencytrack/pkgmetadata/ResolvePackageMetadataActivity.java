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
package org.dependencytrack.pkgmetadata;

import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;
import org.dependencytrack.dex.api.Activity;
import org.dependencytrack.dex.api.ActivityContext;
import org.dependencytrack.dex.api.ActivitySpec;
import org.dependencytrack.dex.api.failure.ApplicationFailureException;
import org.dependencytrack.dex.api.failure.TerminalApplicationFailureException;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Repository;
import org.dependencytrack.model.RepositoryType;
import org.dependencytrack.persistence.jdbi.PackageArtifactMetadataDao;
import org.dependencytrack.persistence.jdbi.PackageMetadataDao;
import org.dependencytrack.pkgmetadata.resolution.api.HashAlgorithm;
import org.dependencytrack.pkgmetadata.resolution.api.PackageArtifactMetadata;
import org.dependencytrack.pkgmetadata.resolution.api.PackageMetadata;
import org.dependencytrack.pkgmetadata.resolution.api.PackageMetadataResolver;
import org.dependencytrack.pkgmetadata.resolution.api.PackageMetadataResolverFactory;
import org.dependencytrack.pkgmetadata.resolution.api.PackageRepository;
import org.dependencytrack.pkgmetadata.resolution.api.RetryableResolutionException;
import org.dependencytrack.plugin.runtime.NoSuchExtensionException;
import org.dependencytrack.plugin.runtime.NoSuchExtensionPointException;
import org.dependencytrack.plugin.runtime.PluginManager;
import org.dependencytrack.proto.internal.workflow.v1.ResolvePackageMetadataActivityArg;
import org.dependencytrack.secret.management.SecretManager;
import org.dependencytrack.util.InternalComponentIdentifier;
import org.dependencytrack.util.PurlUtil;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;

import java.time.Instant;
import java.util.Collection;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;

import static org.dependencytrack.common.MdcKeys.MDC_PKG_METADATA_RESOLVER_NAME;
import static org.dependencytrack.common.MdcKeys.MDC_PKG_REPOSITORY_IDENTIFIER;
import static org.dependencytrack.common.MdcKeys.MDC_PURL;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.useJdbiTransaction;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;

/**
 * @since 5.7.0
 */
@ActivitySpec(name = "resolve-purl-metadata", defaultTaskQueue = "package-metadata-resolutions")
public final class ResolvePackageMetadataActivity implements Activity<ResolvePackageMetadataActivityArg, Void> {

    private static final Logger LOGGER = LoggerFactory.getLogger(ResolvePackageMetadataActivity.class);
    private static final int FLUSH_BATCH_SIZE = 25;

    private final PluginManager pluginManager;
    private final SecretManager secretManager;

    public ResolvePackageMetadataActivity(PluginManager pluginManager, SecretManager secretManager) {
        this.pluginManager = pluginManager;
        this.secretManager = secretManager;
    }

    @Override
    public @Nullable Void execute(
            ActivityContext ctx,
            @Nullable ResolvePackageMetadataActivityArg arg) throws Exception {
        if (arg == null || arg.getPurlsList().isEmpty()) {
            return null;
        }

        final String resolverName = arg.getResolverName();
        final List<String> purlStrings = arg.getPurlsList();

        if (resolverName.isEmpty()) {
            // The resolver name is empty when no resolver exists that
            // supports the given batch of PURLs. In this case, simply
            // store empty results from preventing these PURLs to become
            // resolution candidates again in the next batch.
            final var buffer = new ResultBuffer();
            for (final String purlStr : purlStrings) {
                buffer.addEmptyResult(purlStr);
            }
            buffer.flush();
            return null;
        }

        try (var ignoredMdcResolver = MDC.putCloseable(MDC_PKG_METADATA_RESOLVER_NAME, resolverName)) {
            final PackageMetadataResolverFactory resolverFactory = getResolverFactory(resolverName);

            // Determine which PURLs have already been resolved. In case the activity was
            // restarted (i.e. retry or previously interrupted), it may already have made
            // progress in this batch.
            final Set<String> recentlyResolvedPurls = getRecentlyResolvedPurls(purlStrings);

            final var repoByPurlType = new HashMap<String, List<Repository>>();
            final var passwordByRepoTypeAndName = new HashMap<String, Optional<String>>();

            final var internalIdentifier = new InternalComponentIdentifier();
            final Function<PackageURL, Boolean> isInternalFunc = purl -> isInternal(purl, internalIdentifier);

            final var resultBuffer = new ResultBuffer();

            try (final PackageMetadataResolver resolver = resolverFactory.create()) {
                for (final String purlStr : purlStrings) {
                    if (Thread.interrupted()) {
                        resultBuffer.flush();
                        throw new InterruptedException("Interrupted before all PURLs could be resolved");
                    }
                    ctx.maybeHeartbeat();

                    MDC.put(MDC_PURL, purlStr);
                    try {
                        if (recentlyResolvedPurls.contains(purlStr)) {
                            LOGGER.debug("PURL already resolved recently; Skipping");
                            continue;
                        }

                        processPurl(
                                purlStr,
                                resolverFactory,
                                resolver,
                                repoByPurlType,
                                passwordByRepoTypeAndName,
                                isInternalFunc,
                                resultBuffer);
                    } catch (InterruptedException e) {
                        resultBuffer.flush();
                        throw e;
                    } catch (RetryableResolutionException e) {
                        resultBuffer.flush();
                        throw new ApplicationFailureException(e.getMessage(), e, e.retryAfter());
                    } catch (Exception e) {
                        LOGGER.warn("Failed to resolve metadata; persisting empty result", e);
                        resultBuffer.addEmptyResult(purlStr);
                    } finally {
                        MDC.remove(MDC_PURL);
                    }

                    resultBuffer.maybeFlush();
                }
            }

            resultBuffer.flush();
        }

        return null;
    }

    private void processPurl(
            String purlStr,
            PackageMetadataResolverFactory resolverFactory,
            PackageMetadataResolver resolver,
            Map<String, List<Repository>> repoByPurlType,
            Map<String, Optional<String>> passwordByRepoTypeAndName,
            Function<PackageURL, Boolean> isInternalFunc,
            ResultBuffer buffer) throws Exception {
        final PackageURL purl;
        try {
            purl = new PackageURL(purlStr);
        } catch (MalformedPackageURLException e) {
            LOGGER.warn("Failed to parse PURL; Assuming no metadata", e);
            buffer.addEmptyResult(purlStr);
            return;
        }

        final PackageURL normalizedPurl = resolverFactory.normalize(purl);
        if (normalizedPurl == null) {
            // This should be very rare, as normalization was already applied
            // when preparing the PURL batch handed to this activity.
            buffer.addEmptyResult(purlStr);
            return;
        }

        final ResolutionResult result = resolve(
                normalizedPurl,
                resolverFactory,
                resolver,
                repoByPurlType,
                passwordByRepoTypeAndName,
                isInternalFunc);
        if (result != null) {
            buffer.addResult(purl, result);
        } else {
            buffer.addEmptyResult(purlStr);
        }
    }

    private record ResolutionResult(
            PackageMetadata packageMetadata,
            @Nullable String repositoryIdentifier,
            String resolver) {
    }

    private @Nullable ResolutionResult resolve(
            PackageURL normalizedPurl,
            PackageMetadataResolverFactory resolverFactory,
            PackageMetadataResolver resolver,
            Map<String, List<Repository>> repoByPurlType,
            Map<String, Optional<String>> passwordByRepoTypeAndName,
            Function<PackageURL, Boolean> isInternalFunc) throws Exception {
        if (resolverFactory.requiresRepository()) {
            final List<Repository> repos = repoByPurlType.computeIfAbsent(
                    normalizedPurl.getType(),
                    this::getRepositoriesByPurlType);
            if (repos.isEmpty()) {
                LOGGER.debug("No repositories found");
                return null;
            }

            final boolean internal = isInternalFunc.apply(normalizedPurl);
            for (final Repository repo : repos) {
                // Only resolve internal packages against internal repositories.
                if (!Objects.equals(repo.isInternal(), internal)) {
                    continue;
                }

                try (var ignoredMdcRepo = MDC.putCloseable(MDC_PKG_REPOSITORY_IDENTIFIER, repo.getIdentifier())) {
                    String password = null;
                    if (repo.isAuthenticationRequired() && repo.getPassword() != null) {
                        password = passwordByRepoTypeAndName
                                .computeIfAbsent(
                                        "%s:%s".formatted(repo.getType(), repo.getIdentifier()),
                                        ignored -> {
                                            final String secret = secretManager.getSecretValue(repo.getPassword());
                                            if (secret == null) {
                                                LOGGER.warn("""
                                                        Repository requires authentication, but the configured password \
                                                        cannot be resolved to a secret. Configure a valid secret, or disable \
                                                        the repository to get rid of this warning.""");
                                                return Optional.empty();
                                            }

                                            return Optional.of(secret);
                                        })
                                .orElse(null);
                        if (password == null) {
                            continue;
                        }
                    }

                    final var packageRepository = new PackageRepository(
                            repo.getIdentifier(),
                            repo.getUrl(),
                            repo.isAuthenticationRequired()
                                    ? repo.getUsername()
                                    : null,
                            password);


                    LOGGER.debug("Resolving metadata from repository");
                    final PackageMetadata result = resolver.resolve(normalizedPurl, packageRepository);
                    if (result != null) {
                        return new ResolutionResult(result, repo.getIdentifier(), resolverFactory.extensionName());
                    }
                }
            }
        } else {
            LOGGER.debug("Resolving metadata");
            final PackageMetadata result = resolver.resolve(normalizedPurl, null);
            if (result != null) {
                return new ResolutionResult(result, null, resolverFactory.extensionName());
            }
        }

        return null;
    }

    private PackageMetadataResolverFactory getResolverFactory(String resolverName) {
        try {
            return pluginManager.getFactory(PackageMetadataResolver.class, resolverName);
        } catch (NoSuchExtensionPointException | NoSuchExtensionException e) {
            throw new TerminalApplicationFailureException(
                    "No resolver factory found for name: %s".formatted(resolverName));
        }
    }

    private List<Repository> getRepositoriesByPurlType(String purlType) {
        final var repoType = RepositoryType.ofPurlType(purlType);
        if (repoType == RepositoryType.UNSUPPORTED) {
            return List.of();
        }

        return withJdbiHandle(handle -> handle
                .createQuery(/* language=SQL */ """
                        SELECT *
                          FROM "REPOSITORY"
                         WHERE "TYPE" = :type
                           AND "ENABLED"
                         ORDER BY "RESOLUTION_ORDER"
                        """)
                .bind("type", repoType.name())
                .mapToBean(Repository.class)
                .list());
    }

    private static Set<String> getRecentlyResolvedPurls(Collection<String> purls) {
        return withJdbiHandle(handle -> handle
                .createQuery(/* language=SQL */ """
                        SELECT "PURL"
                          FROM "PACKAGE_ARTIFACT_METADATA"
                         WHERE "PURL" = ANY(:purls)
                           AND "RESOLVED_AT" > NOW() - INTERVAL '5 minutes'
                        """)
                .bindArray("purls", String.class, purls)
                .mapTo(String.class)
                .collect(Collectors.toSet()));
    }

    private static boolean isInternal(
            PackageURL purl,
            InternalComponentIdentifier internalIdentifier) {
        if (!internalIdentifier.hasPatterns()) {
            return false;
        }

        final var component = new Component();
        component.setGroup(purl.getNamespace());
        component.setName(purl.getName());

        return internalIdentifier.isInternal(component);
    }

    private static final class ResultBuffer {

        private final LinkedHashMap<String, org.dependencytrack.model.PackageMetadata> pkgMetadataByPurl = new LinkedHashMap<>();
        private final LinkedHashMap<String, org.dependencytrack.model.PackageArtifactMetadata> artifactMetadataByPurl = new LinkedHashMap<>();

        void addResult(PackageURL purl, ResolutionResult resolutionResult) {
            final PackageMetadata resolvedMetadata = resolutionResult.packageMetadata();
            final String repositoryIdentifier = resolutionResult.repositoryIdentifier();
            final String resolverName = resolutionResult.resolver();
            final Instant resolvedAt = resolvedMetadata.resolvedAt();

            final PackageURL packagePurl = PurlUtil.silentPurlPackageOnly(purl);
            final var packageMetadata = new org.dependencytrack.model.PackageMetadata(
                    packagePurl,
                    resolvedMetadata.latestVersion(),
                    resolvedMetadata.latestVersionPublishedAt(),
                    resolvedAt,
                    repositoryIdentifier,
                    resolverName);
            pkgMetadataByPurl.merge(
                    packagePurl.canonicalize(),
                    packageMetadata,
                    (existing, incoming) -> existing.latestVersion() != null ? existing : incoming);

            final PackageArtifactMetadata resolvedArtifactMetadata = resolvedMetadata.artifactMetadata();
            if (resolvedArtifactMetadata != null) {
                artifactMetadataByPurl.put(
                        purl.canonicalize(),
                        new org.dependencytrack.model.PackageArtifactMetadata(
                                purl,
                                packagePurl,
                                resolvedArtifactMetadata.hashes().get(HashAlgorithm.MD5),
                                resolvedArtifactMetadata.hashes().get(HashAlgorithm.SHA1),
                                resolvedArtifactMetadata.hashes().get(HashAlgorithm.SHA256),
                                resolvedArtifactMetadata.hashes().get(HashAlgorithm.SHA512),
                                resolvedArtifactMetadata.publishedAt(),
                                resolverName,
                                repositoryIdentifier,
                                resolvedAt));
            } else {
                artifactMetadataByPurl.putIfAbsent(
                        purl.canonicalize(),
                        new org.dependencytrack.model.PackageArtifactMetadata(
                                purl, packagePurl, null, null, null, null, null,
                                resolverName, repositoryIdentifier, resolvedAt));
            }
        }

        void addEmptyResult(String purlStr) {
            final PackageURL purl = PurlUtil.silentPurl(purlStr);
            if (purl == null) {
                return;
            }

            final var resolvedAt = Instant.now();
            final PackageURL packagePurl = PurlUtil.silentPurlPackageOnly(purl);
            pkgMetadataByPurl.merge(
                    packagePurl.canonicalize(),
                    new org.dependencytrack.model.PackageMetadata(packagePurl, null, null, resolvedAt, null, null),
                    (existing, incoming) -> existing.latestVersion() != null ? existing : incoming);
            artifactMetadataByPurl.putIfAbsent(
                    purl.toString(),
                    new org.dependencytrack.model.PackageArtifactMetadata(
                            purl, packagePurl, null, null, null, null, null, null, null, resolvedAt));
        }

        void maybeFlush() {
            if (pkgMetadataByPurl.size() >= FLUSH_BATCH_SIZE) {
                flush();
            }
        }

        void flush() {
            if (pkgMetadataByPurl.isEmpty() && artifactMetadataByPurl.isEmpty()) {
                return;
            }

            useJdbiTransaction(handle -> {
                if (!pkgMetadataByPurl.isEmpty()) {
                    final int modified = new PackageMetadataDao(handle).upsertAll(pkgMetadataByPurl.values());
                    LOGGER.debug("Modified {} package metadata records", modified);
                }
                if (!artifactMetadataByPurl.isEmpty()) {
                    final int modified = new PackageArtifactMetadataDao(handle).upsertAll(artifactMetadataByPurl.values());
                    LOGGER.debug("Modified {} package artifact metadata records", modified);
                }
            });

            pkgMetadataByPurl.clear();
            artifactMetadataByPurl.clear();
        }

    }

}
