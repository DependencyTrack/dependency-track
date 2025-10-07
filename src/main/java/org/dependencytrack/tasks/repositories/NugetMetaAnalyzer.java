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

import alpine.common.logging.Logger;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.packageurl.PackageURL;
import org.apache.http.HttpStatus;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.util.EntityUtils;
import org.apache.maven.artifact.versioning.ComparableVersion;
import org.dependencytrack.exception.MetaAnalyzerException;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.RepositoryType;
import org.json.JSONArray;
import org.json.JSONObject;

import java.io.IOException;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.time.temporal.TemporalAccessor;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.concurrent.TimeUnit;

/**
 * An IMetaAnalyzer implementation that supports Nuget.
 * <p>
 * Excludes pre-release and unlisted versions. Pre-release versions will be considered if no stable release exists.
 * Unlisted versions are excluded because they have been deliberately hidden for a specific safety reason.
 * To quote <a href="https://learn.microsoft.com/en-us/nuget/nuget-org/policies/deleting-packages">the Microsoft Nuget
 * docs</a>:
 * <blockquote>"Unlisting a package version hides it from search and from nuget.org package details page. This allows
 * existing users of the package to continue using it but reduces new adoption since the package is not visible in
 * search".</blockquote>
 * For an example package, see
 * <a href="https://www.nuget.org/packages/Microsoft.Data.SqlClient/6.1.0">Microsoft.Data.SqlClient/6.1.0</a>
 * which states:
 * <blockquote>This package has been deprecated as it has critical bugs</blockquote> and
 * <blockquote>The owner has unlisted this package. This could mean that the package is deprecated, has security
 * vulnerabilities or shouldn't be used anymore.</blockquote>
 * Dependency Track won't prevent users from using an unlisted package, but it won't encourage it.
 * <p>
 * We do not use the PackageBaseAddress resource to retrieve version information - it would be faster and simpler
 * but, to <a href="https://learn.microsoft.com/en-us/nuget/api/package-base-address-resource">quote Microsoft</a>:
 * <blockquote>This list contains both listed and unlisted package versions.</blockquote>
 * Artifactory doesn't provide the PackageBaseAddress resource,
 * <a href="https://learn.microsoft.com/en-us/nuget/api/overview">despite Microsoft stating it is required</a>. JFrog
 * <a href="https://jfrog.com/help/r/jfrog-artifactory-documentation/nuget-repositories">state here it is not supported
 * as at September 2025./a>.
 * <p>
 * Artifactory also doesn't provide "published" data as of August 2025 so no dates will be included in the response from
 * those feeds. Other third party feeds may also omit the published dates.
 *
 * @author Steve Springett
 * @since 3.4.0
 */
public class NugetMetaAnalyzer extends AbstractMetaAnalyzer {

    private static final Logger LOGGER = Logger.getLogger(NugetMetaAnalyzer.class);

    private static final String DEFAULT_BASE_URL = "https://api.nuget.org/v3/index.json";
    private static final String NUGET_KEY_UPPER = "upper";
    private static final String NUGET_KEY_ITEMS = "items";

    private static final Cache<String, String> REPO_REGISTRATION_URL_CACHE = Caffeine.newBuilder()
            .maximumSize(100)
            .expireAfterWrite(15, TimeUnit.MINUTES)
            .build();

    private String serviceIndexUrl;
    private String registrationsBaseUrl = "";


    NugetMetaAnalyzer() {
        this.baseUrl = DEFAULT_BASE_URL;
    }


    /**
     * Sets the repository base URL which will then be used to retrieve and parse the service index. If the user has
     * specified a repo URL ending with index.json, it should be considered "fully qualified" and used as is to maximise
     * compatability with non-nuget.org repos such as Artifactory. If not, preserve the previous Dependency Track
     * behaviour of appending the nuget.org index to the supplied URL.
     * @param baseUrl the base URL to the repository
     */
    @Override
    public void setRepositoryBaseUrl(String baseUrl) {
        super.setRepositoryBaseUrl(baseUrl);

        if (baseUrl.toLowerCase().endsWith("index.json")) {
            this.serviceIndexUrl = baseUrl;
        } else {
            this.serviceIndexUrl = stripTrailingSlash(baseUrl) + "/v3/index.json";
        }

        this.setRegistrationsBaseUrl(REPO_REGISTRATION_URL_CACHE.get(this.serviceIndexUrl, key -> findRegistrationsBaseUrl()));
    }

    /**
     * Sets the RegistrationsBaseUrl to be used to retrieve package metadata. This is primarily intended
     * for testing as setRepositoryBaseUrl should find and set the best URL automatically. Call this method AFTER
     * setRepositoryBaseUrl to ensure your value is not overridden.
     *
     * @param registrationsBaseUrlStem Registrations URL to be set
     */
    public void setRegistrationsBaseUrl(String registrationsBaseUrlStem) {
        if(registrationsBaseUrlStem == null || registrationsBaseUrlStem.isBlank()) {
            return;
        }
        this.registrationsBaseUrl = stripTrailingSlash(registrationsBaseUrlStem) + "/%s/%s.json";
    }

    private static String stripTrailingSlash(String input) {
        if (input == null || input.isBlank()) {
            return input;
        }
        return input.endsWith("/") ? input.substring(0, input.length() - 1) : input;
    }

    /**
     * {@inheritDoc}
     */
    public boolean isApplicable(final Component component) {
        return component.getPurl() != null && PackageURL.StandardTypes.NUGET.equals(component.getPurl().getType());
    }

    /**
     * {@inheritDoc}
     */
    public RepositoryType supportedRepositoryType() {
        return RepositoryType.NUGET;
    }

    /**
     * {@inheritDoc}
     */
    public MetaModel analyze(final Component component) {

        if(component == null) {
            throw new IllegalArgumentException("Component cannot be null");
        }

        final MetaModel meta = new MetaModel(component);
        if (component.getPurl() != null) {
            LOGGER.debug("Analyzing component: " + component.getPurl().getName() + " (Internal: " + component.isInternal() + ")");
            performVersionCheck(meta, component);
        }
        LOGGER.debug("Results: " + meta);
        return meta;
    }

    /**
     * Attempts to find the latest version of the supplied component and return its published date, if one exists.
     * Ignores pre-release and unlisted versions.
     * @param meta {@link MetaModel} to be updated with detected version information
     * @param component {@link Component} to be looked up in the NuGet repo
     */
    private void performVersionCheck(final MetaModel meta, final Component component) {

        if (registrationsBaseUrl == null || registrationsBaseUrl.isBlank()) {
            LOGGER.debug("Registration URL not defined for repo " + this.serviceIndexUrl + " - skipping version check");
            return;
        }

        LOGGER.debug("Performing version check for: " + component.getPurl().getName() + " using " + registrationsBaseUrl);

        try {
            final var packageRegistrationRoot = fetchPackageRegistrationIndex(registrationsBaseUrl, component);

            if(packageRegistrationRoot == null) {
                return;
            }

            // Search for a release version first...
            AbridgedNugetCatalogEntry abridgedNugetCatalogEntry = findLatestViaRegistrations(packageRegistrationRoot, false);

            // ... then try again if none found, looking for the latest pre-release version
            if (abridgedNugetCatalogEntry == null) {
                abridgedNugetCatalogEntry = findLatestViaRegistrations(packageRegistrationRoot, true);
            }

            if (abridgedNugetCatalogEntry != null) {
                meta.setLatestVersion(abridgedNugetCatalogEntry.getVersion());
                meta.setPublishedTimestamp(abridgedNugetCatalogEntry.getPublishedTimestamp());
            }

        } catch (IOException e) {
            handleRequestException(LOGGER, e);
        } catch (Exception ex) {
            throw new MetaAnalyzerException(ex);
        }
    }

    /**
     * Retrieves the package registration index for the specified component
     * (e.g. https://api.nuget.org/v3/registration5-gz-semver2/microsoft.data.sqlclient/index.json) and converts to JSON
     * @param registrationsBaseUrl Registration base URL to look up package info
     * @param component Component for which retrieve package registration data should be retrieved
     * @return JSONObject containing package data if found or null if data not found
     * @throws IOException if HTTP request errors
     */
    private JSONObject fetchPackageRegistrationIndex(final String registrationsBaseUrl, final Component component) throws IOException {
        final String idLower = urlEncode(component.getPurl().getName().toLowerCase());
        final String indexUrl = String.format(registrationsBaseUrl, idLower, "index");

        try (final CloseableHttpResponse resp = processHttpRequest(indexUrl)) {
            if (resp.getStatusLine().getStatusCode() != HttpStatus.SC_OK || resp.getEntity() == null) {
                handleUnexpectedHttpResponse(LOGGER, indexUrl, resp.getStatusLine().getStatusCode(), resp.getStatusLine().getReasonPhrase(), component);
                return null;
            }
            return new JSONObject(EntityUtils.toString(resp.getEntity()));
        }
    }

    /**
     * Parses the NuGet Registrations to find latest version information. Handles both inline items and paged items.
     * Sorts pages in descending order by the upper version number - if a listed, final version can be found in that
     * page, it will be returned or pages will be searched in descending order until a match is found.
     * @param registrationData Registrations to be searched
     * @return Version metadata if a suitable version found, or null if not
     * @throws IOException if network error occurs
     */
    private AbridgedNugetCatalogEntry findLatestViaRegistrations(final JSONObject registrationData, final boolean includePreRelease) throws IOException {

        final JSONArray pages = registrationData == null ? null : registrationData.optJSONArray(NUGET_KEY_ITEMS);

        if (pages == null || pages.isEmpty()) {
            return null;
        }

        // Build a list of pages sorted by descending "upper" property.
        final List<JSONObject> pageUpperBounds = new ArrayList<>();
        for (int i = 0; i < pages.length(); i++) {
            final JSONObject page = pages.optJSONObject(i);
            if (page != null && page.has(NUGET_KEY_UPPER)) {
                pageUpperBounds.add(page);
            }
        }

        // Sort upper page bounds in descending order to get newest page first e.g, [ "6.1.0", "5.1.0" ]
        pageUpperBounds.sort((pageOne, pageTwo) -> {
            final ComparableVersion pageOneUpper = new ComparableVersion(pageOne.optString(NUGET_KEY_UPPER, "0"));
            final ComparableVersion pageTwoUpper = new ComparableVersion(pageTwo.optString(NUGET_KEY_UPPER, "0"));
            return pageTwoUpper.compareTo(pageOneUpper); // descending
        });

        for (final JSONObject page : pageUpperBounds) {
            try {
                final JSONArray leaves = resolveLeaves(page);
                final AbridgedNugetCatalogEntry bestOnPage = findHighestVersionFromLeaves(leaves, includePreRelease);
                if (bestOnPage != null) {
                    return bestOnPage;
                }
            } catch (MetaAnalyzerException ex) {
                // Reporting handled in resolveLeaves - return null to avoid returning incorrect version from any page
                return null;
            }
        }

        // No suitable version found
        return null;
    }

    /**
     * Parse the page JSON to find item leaves, retrieving data from the repo if needed. Returns null if neither
     * inline items nor a fetchable @id exist/succeed.
     * @param page Page to be parsed
     * @return JSONArray containing leaf data if available, null if not
     * @throws IOException if network error occurs
     * @throws MetaAnalyzerException if the repo returns an unexpected result
     */
    private JSONArray resolveLeaves(final JSONObject page) throws IOException, MetaAnalyzerException {
        if (page == null) {
            return null;
        }

        final JSONArray inline = page.optJSONArray(NUGET_KEY_ITEMS);
        if (inline != null && !inline.isEmpty()) {
            LOGGER.trace("Processing inline catalog entries");
            return inline;
        }

        final String pageUrl = page.optString("@id", null);
        if (pageUrl == null || pageUrl.isBlank()) {
            return null;
        }

        LOGGER.trace("Retrieving catalog entry page " + pageUrl);
        try (final CloseableHttpResponse resp = processHttpRequest(pageUrl)) {
            if (resp.getStatusLine().getStatusCode() == HttpStatus.SC_OK && resp.getEntity() != null) {
                final var pageJson = new JSONObject(EntityUtils.toString(resp.getEntity()));
                return pageJson.optJSONArray(NUGET_KEY_ITEMS);
            } else {
                handleUnexpectedHttpResponse(LOGGER, pageUrl, resp.getStatusLine().getStatusCode(), resp.getStatusLine().getReasonPhrase(), null);
                throw new MetaAnalyzerException("Could not retrieve catalog entry page when processing " + pageUrl);
            }
        }
    }

    /**
     * Scan the supplied leaves to extract the latest listed version. NuGet does not guarantee release order
     * so scan the entire array although, anecdotally, the collection does generally appear to be in ascending order
     * @param leaves Items to be scanned
     * @param includePreRelease include pre-release versions in latest version lookup
     * @return {@link AbridgedNugetCatalogEntry containing the latest version found in the leaves collection
     */
    private AbridgedNugetCatalogEntry findHighestVersionFromLeaves(final JSONArray leaves, final boolean includePreRelease) {

        if (leaves == null || leaves.isEmpty()) {
            return null;
        }

        AbridgedNugetCatalogEntry bestEntry = null;
        ComparableVersion newestVersionFound = null;

        for (int i = 0; i < leaves.length(); i++) {
            final JSONObject leaf = leaves.optJSONObject(i);
            AbridgedNugetCatalogEntry entry = null;

            if (leaf.has("catalogEntry")) {
                entry = parseCatalogEntry(leaf.optJSONObject("catalogEntry"));
            }

            if (entry == null || entry.getVersion() == null || (isPreRelease(entry.getVersion()) && !includePreRelease)) {
                continue;
            }

            final ComparableVersion entryVersion = new ComparableVersion(entry.getVersion());
            if (newestVersionFound == null || entryVersion.compareTo(newestVersionFound) > 0) {
                newestVersionFound = entryVersion;
                bestEntry = entry;
            }
        }

        return bestEntry;
    }

    /**
     * Parse a single catalog entry to extract the version and published information. Could be extended to include other
     * fields (such as listed) if required. Returns null immediately if the entry is unlisted.
     * @param catalogEntry Catalog entry to be parsed
     * @return {@link AbridgedNugetCatalogEntry} if version is valid, null if not
     */
    private AbridgedNugetCatalogEntry parseCatalogEntry(final JSONObject catalogEntry) {

        // Listed is optional so assume package is listed unless explicitly hidden
        boolean listed = catalogEntry.optBoolean("listed", true);

        if(!listed) {
            return null;
        }

        var version = catalogEntry.optString("version", null);
        if (version == null || version.isBlank()) {
            return null;
        }

        AbridgedNugetCatalogEntry entry = new AbridgedNugetCatalogEntry();
        entry.setVersion(version);

        var updateTime = catalogEntry.optString("published", null);
        if (updateTime != null) {
            entry.setPublishedTimestamp(parseUpdateTime(updateTime));
        }

        return entry;
    }

    /**
     * NuGet considers a version string with any suffix after a hyphen to be pre-release according to <a
     * href="https://learn.microsoft.com/en-us/nuget/concepts/package-versioning?tabs=semver20sort#pre-release-versions">
     * the documentation</a>. This method could be expanded if we need to cover other rules.
     * @param version Version string to be tested
     * @return True if version matches pre-release conventions, false otherwise
     */
    private boolean isPreRelease(final String version) {
        return version.contains("-");
    }

    /**
     * Connects to the NuGet repo, retrieves the service index and attempts to find the best RegistrationsBaseUrl
     * @return RegistrationsBaseUrl if found, null otherwise
     */
    private String findRegistrationsBaseUrl() {

        JSONObject responseJson = null;

        try (final CloseableHttpResponse resp = processHttpRequest(this.serviceIndexUrl)) {
            if (resp.getStatusLine().getStatusCode() == HttpStatus.SC_OK && resp.getEntity() != null) {
                responseJson = new JSONObject(EntityUtils.toString(resp.getEntity()));
            } else {
                handleUnexpectedHttpResponse(LOGGER, this.serviceIndexUrl, resp.getStatusLine().getStatusCode(), resp.getStatusLine().getReasonPhrase(), null);
                throw new MetaAnalyzerException("Could not initialize NugetMetaAnalyzer - unexpected response from NuGet service. Response code was " + resp.getStatusLine().getStatusCode() + ".");
            }
        } catch (IOException e) {
            handleRequestException(LOGGER, e);
        }

        if (responseJson != null) {
            final JSONArray resources = responseJson.optJSONArray("resources");
            final String regBaseUrl = extractRegistrationBaseUrlFromJson(resources);
            if (regBaseUrl != null) {
                LOGGER.debug("RegistrationsBaseUrl selected: " + regBaseUrl);
                return regBaseUrl;
            }
        }

        LOGGER.debug("Could not find the RegistrationsBaseUrl at " + this.serviceIndexUrl);
        return null;
    }

    /**
     * Attempts to find the "best" RegistrationsBaseUrl from the NuGet service index preferring SemVer 2 with
     * compression, SemVer 2 without compression then non-compressed, non-SemVer2.
     * See <a href="https://learn.microsoft.com/en-us/nuget/api/registration-base-url-resource>for versioning
     * details</a>
     * @param serviceIndexJson JSONArray containing the NuGet repo service index
     * @return RegistrationsBaseUrl or null if none found
     */
    private String extractRegistrationBaseUrlFromJson(JSONArray serviceIndexJson) {

        if (serviceIndexJson == null) {
            return null;
        }

        // Prefer SemVer2 registrations if available
        final JSONObject regsSemver2 = findResourceByType(serviceIndexJson, "RegistrationsBaseUrl/3.6.0");
        if (regsSemver2 != null) {
            return regsSemver2.optString("@id", null);
        }

        // Failing that, check for the gzipped registration hive
        final JSONObject regsGzipped = findResourceByType(serviceIndexJson, "RegistrationsBaseUrl/3.4.0");
        if (regsGzipped != null) {
            return regsGzipped.optString("@id", null);
        }

        // Worst case, check for the non-gzipped version
        final JSONObject fallback = findResourceByType(serviceIndexJson, "RegistrationsBaseUrl");
        if (fallback != null) {
            return fallback.optString("@id", null);
        }

        return null;
    }

    private JSONObject findResourceByType(JSONArray resources, String type) {
        for (int i = 0; i < resources.length(); i++) {
            String resourceType = resources.getJSONObject(i).getString("@type");
            if (resourceType != null && resourceType.toLowerCase().startsWith(type.toLowerCase())) {
                return resources.getJSONObject(i);
            }
        }

        return null;
    }

    /**
     * Attempts to parse a NuGet date time string to a {@link Date}. NuGet repositories may use differing date formats
     * so this method tries a couple of attempts. The
     * <a href="https://learn.microsoft.com/en-us/nuget/api/registration-base-url-resource#catalog-entry">MS
     * spec states that ISO8601 should be used</a> but that standard is flexible when it comes to timezone info.
     * <p>
     * The ISO_INSTANT formatter handles time with timezone and milliseconds ("yyyy-MM-dd'T'HH:mm:ss.SSSXXX") and
     * UTC-only ("yyyy-MM-dd'T'HH:mm:ss'Z'"). A fallback LocalDateTime parser handles cases without a timezone
     * ("yyyy-MM-dd'T'HH:mm:ss").
     * @param nugetDateTimeString Date time string in one of NuGet's permitted formats
     * @return Date if input could be parsed, null if date could not be parsed
     */
    protected Date parseUpdateTime(String nugetDateTimeString) {
        if (nugetDateTimeString == null) {
            return null;
        }

        try {
            TemporalAccessor ta = DateTimeFormatter.ISO_INSTANT.parse(nugetDateTimeString);
            return Date.from(Instant.from(ta));
        } catch (DateTimeParseException e) {
            try {
                LocalDateTime localDateTime = LocalDateTime.parse(nugetDateTimeString);
                return Date.from(localDateTime.atOffset(ZoneOffset.UTC).toInstant());
            } catch (DateTimeParseException e2) {
                return null;
            }
        }
    }

    /**
     * Internal class to collate useful version information from the larger NuGet catalog entry
     */
    private static class AbridgedNugetCatalogEntry {
        private String version;
        private Date publishedTimestamp;

        private String getVersion() {
            return version;
        }

        private void setVersion(String version) {
            this.version = version;
        }

        private Date getPublishedTimestamp() {
            return publishedTimestamp;
        }

        private void setPublishedTimestamp(Date publishedTimestamp) {
            this.publishedTimestamp = publishedTimestamp;
        }

        @Override
        public String toString() {
            return "AbridgedNugetCatalogEntry{" +
                    "version='" + version + '\'' +
                    ", publishedTimestamp=" + publishedTimestamp +
                    '}';
        }
    }

}
