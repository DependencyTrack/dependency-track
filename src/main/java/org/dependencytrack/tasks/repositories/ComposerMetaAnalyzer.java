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
import jakarta.ws.rs.core.UriBuilder;

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
     * @see <a href="https://packagist.org/apidoc#get-package-data">Packagist's API
     *      doc for
     *      "Getting package data - Using the Composer v1 metadata (DEPRECATED)"</a>
     *      Example: https://repo.packagist.org/p/monolog/monolog.json
     */
    private static final String PACKAGE_META_DATA_PATH_PATTERN_V1 = "/p/%package%.json";

    private static final Cache<String, JSONObject> REPO_ROOT_CACHE = Caffeine.newBuilder()
            .expireAfterWrite(1, TimeUnit.HOURS)
            .build();

    /**
     * Some of the properties of the root package.json are documented at
     * https://github.com/composer/composer/blob/main/doc/05-repositories.md
     * Properties to investigate / implement:
     *
     * - security-advisories: very relevant, but only in a VulnerabilityAnalyzer (or
     * mirrored VulnerabilitySource) context
     *
     * - providers-lazy-url: old v1 construct for which I haven't seen any example,
     * in v2 the metadata-url is used for this. seems like it's not relevant for DT
     * - list: returns only package names, seems like repo.packagist.org (and .com?)
     * are the only ones implementing it
     * - providers-api: not relevant
     * - notify-batch: not relevant
     * - providers-url and provider-includes: only relevant to check hashes, so not
     * relevant for DT currently. Replaced by metadata-url in V2 repositories.
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
        final MetaModel meta = new MetaModel(component);
        final String composerPackageName = getComposerPackageName(component);
        if (component.getPurl() == null) {
            return meta;
        }

        final JSONObject repoRoot = getRepoRoot();
        if (repoRoot == null) {
            LOGGER.debug("%s: repoRoot is null for repository %s, fallback to v1 metadata url %s".formatted(composerPackageName, this.repositoryId, PACKAGE_META_DATA_PATH_PATTERN_V1));
            // absence of packages.json shouldn't happen, but let's try to get metadata as
            // we did in <=4.12.2
            return analyzeFromMetadataUrl(meta, component, PACKAGE_META_DATA_PATH_PATTERN_V1);
        }

        // Available packages is finite, so we can use it to determine if the package
        // exists in this repository
        if (repoRoot.has("available-packages")) {
            final JSONArray availablePackages = repoRoot.getJSONArray("available-packages");
            if (!availablePackages.toList().contains(getComposerPackageName(component)) && !repoRoot.has("available-package-patterns")) {
                // According to https://github.com/composer/composer/blob/fb397acaa0648ba2668893e4b786af6465a41696/doc/05-repositories.md?plain=1#L197
                // available-packages should contain ALL the packages in the repo.
                // But in the Composer implementation the patterns are consulted even if available-packages is present and doesn't contain the package
                LOGGER.debug("%s: package not present in available-packages nor available-package-patterns for repository %s".formatted(composerPackageName, this.repositoryId));
                return meta;
            }
        }

        if (repoRoot.has("available-package-patterns")) {
            final JSONArray availablePackagePatterns = repoRoot.getJSONArray("available-package-patterns");
            // handle regex same as Composer does in its code
            boolean found = availablePackagePatterns.toList().stream()
                    .map(Object::toString)
                    .map(pattern -> "(?i)^%s$".formatted(pattern.replaceAll("\\*", ".*")))
                    .anyMatch(pattern -> composerPackageName.matches(pattern));

            if (!found) {
                LOGGER.debug("%s: package doesn't match available-package-patterns in repository %s".formatted(composerPackageName, this.repositoryId));
                return meta;
            }
        }

        if (repoRoot.has("metadata-url")) {
            // presence of metadata-url implies V2 repository, and takes precedence over
            // included packages and other V1 features
            final String packageMetaDataPathPattern = repoRoot.getString("metadata-url");
            LOGGER.debug("%s: using metadata-url pattern from packages.json: %s".formatted(this.repositoryId, packageMetaDataPathPattern));
            return analyzeFromMetadataUrl(meta, component, packageMetaDataPathPattern);
        }

        // initial batch of included pacakges is included in packages.json response
        if (isMinified(repoRoot)) {
            repoRoot.put("packages", expandPackages(repoRoot.getJSONObject("packages")));
        }

        loadIncludedPackages(repoRoot, repoRoot, true);
        // included packages are considered finite, so we can use them for analysis
        // without retrieving the package specific metadata
        if (repoRoot.has("packages")) {
            JSONObject packages = repoRoot.getJSONObject("packages");
            if (!packages.isEmpty()) {
                if (!packages.has(getComposerPackageName(component))) {
                    LOGGER.debug("%s: package not found in repository %s.".formatted(component.getPurl(), this.repositoryId));
                    return meta;
                }
                JSONObject packageVersions = packages.getJSONObject(getComposerPackageName(component));
                return analyzePackageVersions(meta, component, packageVersions);
            }
        }

        // V1 and no included packages, so we have to retrieve the package specific
        // metadata
        LOGGER.debug("%s: no metadata-url pattern and package not found in included packages for repository %s, analyzing using v1 url pattern: %s".formatted(component.getPurl(), this.repositoryId, PACKAGE_META_DATA_PATH_PATTERN_V1));
        return analyzeFromMetadataUrl(meta, component, PACKAGE_META_DATA_PATH_PATTERN_V1);
    }

    private JSONObject getRepoRoot() {
        // Code mimicksed from
        // https://github.com/composer/composer/blob/main/src/Composer/Repository/ComposerRepository.php
        // Retrieve packages.json file, which must be present even for V1 repositories
        String packageJsonUrl = UriBuilder.fromUri(baseUrl).path("packages.json").build().toString();
        return REPO_ROOT_CACHE.get(repositoryId + packageJsonUrl, key -> getRepoRootFromUrl(packageJsonUrl));
    }

    private JSONObject getRepoRootFromUrl(String packageJsonUrl) {
        JSONObject repoRoot = new JSONObject("{}");
        try (final CloseableHttpResponse packageJsonResponse = processHttpRequest(packageJsonUrl)) {
            // Make sure we also cache invalid / empty responses
            if (packageJsonResponse.getStatusLine().getStatusCode() != HttpStatus.SC_OK) {
                LOGGER.warn("Failed to retrieve packages.json from " + packageJsonUrl + " HTTP status code: "
                        + packageJsonResponse.getStatusLine().getStatusCode());
            } else if (packageJsonResponse.getEntity().getContent() == null) {
                LOGGER.warn("%s: Null packages.json from %s".formatted(this.repositoryId, packageJsonUrl));
            } else {
                final String packageJsonString = EntityUtils.toString(packageJsonResponse.getEntity());
                if (JsonUtil.isBlankJson(packageJsonString)) {
                    LOGGER.warn("%s: Empty packages.json from %s".formatted(this.repositoryId, packageJsonUrl));
                } else {
                    repoRoot = new JSONObject(packageJsonString);
                }
            }
        } catch (IOException e) {
            LOGGER.error("%s: Error retrieving packages.json from %s".formatted(this.repositoryId, packageJsonUrl), e);
            handleRequestException(LOGGER, e);
        }
        LOGGER.debug("%s: retrieved packages.json from: %s".formatted(this.repositoryId, packageJsonUrl));
        return repoRoot;
    }

    private void loadIncludedPackages(final JSONObject repoRoot, final JSONObject data, final boolean includesOnly) {
        if (!repoRoot.has("packages") || repoRoot.get("packages") instanceof JSONArray) {
            repoRoot.put("packages", new JSONObject());
        }
        if (!includesOnly && data.has("packages")) {
            boolean minified = isMinified(data);
            JSONObject packages = data.getJSONObject("packages");
            if (minified) {
                packages = expandPackages(packages);
            }

            final JSONObject newPackages = packages;
            newPackages.names().forEach(name -> {
                String packageName = (String) name;
                JSONObject packageVersions = newPackages.getJSONObject(packageName);

                if (!repoRoot.getJSONObject("packages").has(packageName)) {
                    repoRoot.getJSONObject("packages").put(packageName, new JSONObject());
                }

                JSONObject includedPackage = repoRoot.getJSONObject("packages").getJSONObject(packageName);
                final JSONObject finalPackageVersions = packageVersions;
                finalPackageVersions.names().forEach(version -> {
                    includedPackage.put((String) version, finalPackageVersions.getJSONObject((String) version));
                });
            });
        }

        if (data.has("includes")) {
            JSONObject includes = data.getJSONObject("includes");
            includes.names().forEach(name -> {
                String includeFilename = (String) name;
                String includeUrl = UriBuilder.fromUri(baseUrl).path(includeFilename).build().toString();
                try (final CloseableHttpResponse includeResponse = processHttpRequest(includeUrl)) {
                    if (includeResponse.getStatusLine().getStatusCode() != HttpStatus.SC_OK) {
                        LOGGER.warn("Failed to retrieve include " + includeFilename + " HTTP status code: "
                                + includeResponse.getStatusLine().getStatusCode());
                    } else if (includeResponse.getEntity().getContent() == null) {
                        LOGGER.warn("%s: Null include from %s".formatted(this.repositoryId, includeFilename));
                    } else {
                        final String nextDataString = EntityUtils.toString(includeResponse.getEntity());
                        if (JsonUtil.isBlankJson(nextDataString)) {
                            LOGGER.warn("%s: Empty include from %s".formatted(this.repositoryId, includeFilename));
                        } else {
                            JSONObject nextData = new JSONObject(nextDataString);

                            loadIncludedPackages(repoRoot, nextData, false);
                        }
                    }
                } catch (IOException e) {
                    LOGGER.error("%s: Error retrieving include from %s".formatted(this.repositoryId, includeFilename), e);
                    handleRequestException(LOGGER, e);
                }
            });
            // remove processed includes as the repoRoot gets cached and we don't need to
            // retrieve the includes again
            data.remove("includes");
        }
    }

    private MetaModel analyzeFromMetadataUrl(final MetaModel meta, final Component component,
            final String packageMetaDataPathPattern) {
        final String composerPackageMetadataFilename = packageMetaDataPathPattern.replaceAll("%package%",
                getComposerPackageName(component));
        final String url = UriBuilder.fromUri(baseUrl).path(composerPackageMetadataFilename).build().toString();
        try (final CloseableHttpResponse response = processHttpRequest(url)) {
            if (response.getStatusLine().getStatusCode() == HttpStatus.SC_NOT_FOUND) {
                // 404s are valid responses, as the package might not exist in the repository
                return meta;
            }

            if (response.getStatusLine().getStatusCode() != HttpStatus.SC_OK) {
                handleUnexpectedHttpResponse(LOGGER, url, response.getStatusLine().getStatusCode(),
                        response.getStatusLine().getReasonPhrase(), component);
                return meta;
            }
            if (response.getEntity().getContent() == null) {
                return meta;
            }
            String metadataString = EntityUtils.toString(response.getEntity());
            if (JsonUtil.isBlankJson(metadataString)) {
                return meta;
            }
            JSONObject metadataJson = new JSONObject(metadataString);
            final String expectedResponsePackage = getComposerPackageName(component);
            final JSONObject responsePackages = metadataJson.getJSONObject("packages");

            if (!responsePackages.has(expectedResponsePackage)) {
                // the package no longer exists - for v2 there's no example (yet), v1 example
                // https://repo.packagist.org/p/magento/adobe-ims.json
                LOGGER.debug("%s: Package no longer exists in repository %s.". formatted(component.getPurl(), this.repositoryId));
                return meta;
            }

            if (isMinified(metadataJson)) {
                return analyzePackageVersions(meta, component,
                        expandPackageVersions(responsePackages.getJSONArray(expectedResponsePackage)));
            } else {
                return analyzePackageVersions(meta, component, responsePackages.getJSONObject(expectedResponsePackage));
            }
        } catch (IOException e) {
            handleRequestException(LOGGER, e);
        } catch (Exception e) {
            throw new MetaAnalyzerException(e);
        }
        return meta;
    }

    private String getComposerPackageName(final Component component) {
        return component.getPurl().getNamespace() + "/" + component.getPurl().getName();
    }

    private JSONObject expandPackageVersions(final JSONArray packageVersions) {
        // Convert JSONArray to JSONObject with "version" as the key to align with
        // existing v1 code (Composer does this as well)
        final JSONObject finalVersionedPackages = new JSONObject();
        packageVersions.forEach(item -> {
            JSONObject composerPackage = (JSONObject) item;
            String version = composerPackage.getString("version");
            finalVersionedPackages.put(version, composerPackage);
        });
        return finalVersionedPackages;
    }

    private JSONObject expandPackages(JSONObject packages) {
        JSONObject result = new JSONObject();
        packages.names().forEach(name -> {
            String packageName = (String) name;
            JSONArray packageVersionsMinified = packages.getJSONArray(packageName);
            JSONObject packageVersions = expandPackageVersions(packageVersionsMinified);
            result.put(packageName, packageVersions);
        });
        return result;
    }

    private MetaModel analyzePackageVersions(final MetaModel meta, Component component, JSONObject packageVersions) {
        final ComparableVersion latestVersion = new ComparableVersion(stripLeadingV(component.getPurl().getVersion()));
        final DateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssXXX");

        LOGGER.debug("%s: analyzing package versions in %s: ".formatted(component.getPurl(), this.repositoryId));
        packageVersions.names().forEach(item -> {
            JSONObject packageVersion = packageVersions.getJSONObject((String) item);
            // Sometimes the JSON key differs from the the version inside the JSON value. The latter is leading.
            String version = packageVersion.getString("version");
            if (version.startsWith("dev-") || version.endsWith("-dev")) {
                // dev versions are excluded, since they are not pinned but a VCS-branch.
                // this case doesn't seem to happen anymore with V2, as dev (untagged) releases
                // are not part of the response anymore
                return;
            }

            // Some (old?) repositories like composer.amasty.com/enterprise do not include a
            // 'version_normalized' field
            // TODO Should we attempt to normalize ourselves? The PHP code uses something
            // that results in 4 parts instead of 3, i.e. 2.3.8.0 instead of 2.3.8. Not sure
            // if that works with Semver4j
            String version_normalized = packageVersion.getString("version");
            if (packageVersion.has("version_normalized")) {
                version_normalized = packageVersion.getString("version_normalized");
            }

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
                    LOGGER.warn("%s: An error occurred while parsing time in repository %s".formatted(component.getPurl(), this.repositoryId), e);
                }
            } else {
                // TODO some repositories like packages.drupal.org include a 'dateStamp' field,
                // example 1700068743
                // Some repositories like packages.drupal.org and composer.amasty.com/entprise
                // do not include the name field for a version, so print purl
                LOGGER.warn("%s: Field 'time' not present in metadata in repository %s".formatted(component.getPurl(), this.repositoryId));
            }
        });
        return meta;
    }

    private static String stripLeadingV(String s) {
        return s.startsWith("v") || s.startsWith("V")
                ? s.substring(1)
                : s;
    }

    private static boolean isMinified(JSONObject data) {
        return data.has("minified") && data.getString("minified").equals("composer/2.0");
    }
}
