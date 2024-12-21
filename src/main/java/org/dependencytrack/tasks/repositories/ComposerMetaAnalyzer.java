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
package org.dependencytrack.tasks.repositories;

import java.io.IOException;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.concurrent.TimeUnit;

import org.apache.http.HttpStatus;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.util.EntityUtils;
import org.apache.maven.artifact.versioning.ComparableVersion;
import org.dependencytrack.exception.MetaAnalyzerException;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.RepositoryType;
import org.dependencytrack.util.JsonUtil;
import org.json.JSONArray;
import org.json.JSONObject;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.packageurl.PackageURL;

import alpine.common.logging.Logger;

/**
 * An IMetaAnalyzer implementation that supports Composer.
 *
 * @author Szabolcs (Szasza) Palmer
 * @since 4.1.0
 */
public class ComposerMetaAnalyzer extends AbstractMetaAnalyzer {

    private static final Logger LOGGER = Logger.getLogger(ComposerMetaAnalyzer.class);
    private static final String DEFAULT_BASE_URL = "https://repo.packagist.org";

    /**
     * @see <a href="https://packagist.org/apidoc#get-package-data">Packagist's API doc for "Getting package data - Using the Composer v1 metadata (DEPRECATED)"</a>
     * Example: https://repo.packagist.org/p/monolog/monolog.json
     */
    private static final String PACKAGE_META_DATA_PATH_PATTERN_V1 = "/p/%package%.json";

    private static final Cache<String, JSONObject> REPO_ROOT_CACHE = Caffeine.newBuilder()
        .expireAfterWrite(6, TimeUnit.MINUTES)
        .build();

    /**
     * Some of the properties of the root package.json are documented at https://github.com/composer/composer/blob/main/doc/05-repositories.md
     * Properties to investigate / implement:
     * - packages: very relevant as some repositories only provide their metadata this way (packages.shopware.com)
     * - includes: very relevant as some repositories only provide their metadata this way (packages.mirasvit.com, composer.magepal.com)
     * - available-packages and available-package-patterns: relevant to limit traffic to specific repositories
     * - security-advisories: very relevant, but only in a VulnerabilityAnalyzer (or mirrored VulnerabilitySource) context
     * - list: returns only package names, seems like repo.packagist.org (and .com?) are the only ones implementing it
     * - providers-api: not relevant
     * - notify-batch: not relevant
     * - providers-url and provider-includes: only relevant to check hashes, so not relevant for DT currently. Replaced by metadata-url in V2 repositories.
     * - providers-lazy-url: not relevant
     * - providers-api: not relevant
     * - search: not relevant
     */

    ComposerMetaAnalyzer() {
        this.baseUrl = DEFAULT_BASE_URL;
    }

    /**
     * {@inheritDoc}
     */
    public boolean isApplicable(final Component component) {
        return component.getPurl() != null && PackageURL.StandardTypes.COMPOSER.equals(component.getPurl().getType());
    }

    /**
     * {@inheritDoc}
     */
    public RepositoryType supportedRepositoryType() {
        return RepositoryType.COMPOSER;
    }

    /**
     * {@inheritDoc}
     */
    public MetaModel analyze(final Component component) {
        if (component.getPurl() == null) {
            return new MetaModel(component);
        }

        // Code mimicksed from https://github.com/composer/composer/blob/main/src/Composer/Repository/ComposerRepository.php
        // Retrieve packages.json file, which must be present even for V1 repositories
        final String packageJsonUrl = baseUrl + "/packages.json";

        JSONObject repoRoot = REPO_ROOT_CACHE.getIfPresent(packageJsonUrl);
        if (repoRoot == null) {
            try (final CloseableHttpResponse packageJsonResponse = processHttpRequest(packageJsonUrl)) {
                if (packageJsonResponse.getStatusLine().getStatusCode() != HttpStatus.SC_OK) {
                    LOGGER.warn("Failed to retrieve packages.json from " + packageJsonUrl + " HTTP status code: " + packageJsonResponse.getStatusLine().getStatusCode());
                    return new MetaModel(component);
                }

                //Make sure we don't return before caching empty responses
                String packageJsonString = "";
                if (packageJsonResponse.getEntity().getContent() == null) {
                    LOGGER.warn("Null packages.json from " + packageJsonUrl);
                }

                packageJsonString = EntityUtils.toString(packageJsonResponse.getEntity());
                if (JsonUtil.isBlankJson(packageJsonString)) {
                    LOGGER.warn("Empty packages.json from " + packageJsonUrl);
                }

                repoRoot = new JSONObject(packageJsonString);
                // Not sure, but it could be that some repositories provide responses based on credentials
                // We do not have enough information here to include those credentials in the cache key
                // TODO Investigate if repository root metedata can differ per set of authentication credentials
                REPO_ROOT_CACHE.put(packageJsonUrl, repoRoot);
            } catch (IOException e) {
                LOGGER.error("Error retrieving packages.json from " + packageJsonUrl, e);
            }
        }
        if (!repoRoot.has("metadata-url")) {
            // absence of metadat-url implies V2 repository
            return analyzeFromMetadataUrl(component, PACKAGE_META_DATA_PATH_PATTERN_V1);
        }

        final String packageMetaDataPathPattern = repoRoot.getString("metadata-url");
        return analyzeFromMetadataUrl(component, packageMetaDataPathPattern);
    }

    private MetaModel analyzeFromRoot(final Component component, final JSONObject repoRoot) {
        final String packageMetaDataPathPattern = repoRoot.getString("metadata-url");
        return analyzeFromMetadataUrl(component, packageMetaDataPathPattern);
    }


    private MetaModel analyzeFromMetadataUrl(final Component component, final String packageMetaDataPathPattern) {
        String namespace = urlEncode(component.getPurl().getNamespace());
        String name = urlEncode(component.getPurl().getName());

        final String url = baseUrl + packageMetaDataPathPattern.replaceAll("%package%", "%s/%s".formatted(namespace, name));
        try (final CloseableHttpResponse response = processHttpRequest(url)) {
            if (response.getStatusLine().getStatusCode() != HttpStatus.SC_OK) {
                handleUnexpectedHttpResponse(LOGGER, url, response.getStatusLine().getStatusCode(), response.getStatusLine().getReasonPhrase(), component);
                return new MetaModel(component);
            }
            if (response.getEntity().getContent() == null) {
                return new MetaModel(component);
            }
            String metadataString = EntityUtils.toString(response.getEntity());
            if (JsonUtil.isBlankJson(metadataString)) {
                return new MetaModel(component);
            }
            JSONObject metadataJson = new JSONObject(metadataString);
            final String expectedResponsePackage = component.getPurl().getNamespace() + "/" + component.getPurl().getName();
            final JSONObject responsePackages = metadataJson.getJSONObject("packages");

            if (!responsePackages.has(expectedResponsePackage)) {
                // the package no longer exists - for v2 there's no example (yet), v1 example https://repo.packagist.org/p/magento/adobe-ims.json
                return new MetaModel(component);
            }

            if (metadataJson.has("minified") && metadataJson.getString("minified").equals("composer/2.0")) {
                // Convert JSONArray to JSONObject with "version" as the key to align with existing v1 code (Compoer does this as well)
                final JSONArray composerPackageVersions = responsePackages.getJSONArray(expectedResponsePackage);
                JSONObject versionedPackages = new JSONObject();
                composerPackageVersions.forEach(item -> {
                    JSONObject composerPackage = (JSONObject) item;
                    String version = composerPackage.getString("version");
                    versionedPackages.put(version, composerPackage);
                });
                return analyzePackageVersions(component, versionedPackages);
            }
            return analyzePackageVersions(component, responsePackages.getJSONObject(expectedResponsePackage));
        } catch (IOException ex) {
            handleRequestException(LOGGER, ex);
        } catch (Exception ex) {
            throw new MetaAnalyzerException(ex);
        }
        return new MetaModel(component);
    }

    private MetaModel analyzePackageVersions(Component component, JSONObject packageVersions) {
        final MetaModel meta = new MetaModel(component);
        final ComparableVersion latestVersion = new ComparableVersion(stripLeadingV(component.getPurl().getVersion()));
        final DateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssXXX");

        packageVersions.names().forEach(item -> {
            JSONObject packageVersion = packageVersions.getJSONObject((String)item);
            String version =  packageVersion.getString("version");
            if (version.startsWith("dev-") || version.endsWith("-dev")) {
                // dev versions are excluded, since they are not pinned but a VCS-branch.
                // this case doesn't seem to happen anymore with V2, as dev (untagged) releases are not part of the response anymore
                return;
            }

            final String version_normalized = packageVersion.getString("version_normalized");
            ComparableVersion currentComparableVersion = new ComparableVersion(version_normalized);
            if (currentComparableVersion.compareTo(latestVersion) < 0) {
                // smaller version can be skipped
                return;
            }

            latestVersion.parseVersion(stripLeadingV(version_normalized));
            meta.setLatestVersion(version);

            if (packageVersion.has("time")) {
                final String published = packageVersion.getString("time");
                try {
                    meta.setPublishedTimestamp(dateFormat.parse(published));
                } catch (Exception e) {
                    LOGGER.warn("An error occurred while parsing upload time", e);
                }
            } else {
                //TODO some repositories like packages.drupal.org include a 'dateStamp' field, example 1700068743
                // Some repositories like packages.drupal.org do not include the name field for a version, so print purl
                LOGGER.warn("Field 'time' not present in metadata for " + component.getPurl());
            }
        });
        return meta;
    }

    /**
     * Clears the cache of repository root metadata.
     * Needed in unit tests as we currently only have url as a cache key and all unit tests run against localhost...
     */
    protected static void clearRepoRootCache() {
        //TODO Check if this can be done differently, or we can add extra information to the analyzer to have a better cache key
        REPO_ROOT_CACHE.invalidateAll();
    }

    private static String stripLeadingV(String s) {
        return s.startsWith("v") || s.startsWith("V")
                ? s.substring(1)
                : s;
    }
}
