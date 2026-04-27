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
import com.github.packageurl.PackageURL;
import org.apache.http.HttpHeaders;
import org.apache.http.HttpStatus;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.entity.ContentType;
import org.apache.http.util.EntityUtils;
import org.apache.maven.artifact.versioning.ComparableVersion;
import org.dependencytrack.exception.MetaAnalyzerException;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.RepositoryType;
import org.json.JSONArray;
import org.json.JSONObject;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;

import java.io.IOException;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * An IMetaAnalyzer implementation that supports Python package repositories.
 * This analyzer uses the standardized Simple Repository API.
 *
 * @author ch8matt
 */

public class PypiMetaAnalyzer extends AbstractMetaAnalyzer {

    private static final Logger LOGGER = Logger.getLogger(PypiMetaAnalyzer.class);

    private static final String DEFAULT_BASE_URL = "https://pypi.org";

    /**
     * Prefer JSON (PEP 691) but accept HTML (PEP 503) as a fallback.
     */
    private static final String ACCEPT_SIMPLE_API = String.join(", ",
            "application/vnd.pypi.simple.v1+json",
            "application/vnd.pypi.simple.v1+html;q=0.2",
            "text/html;q=0.01");

    /**
     * PEP 503 normalization: lowercase and replace runs of '.', '_' and '-' with a single '-'.
     */
    private static final Pattern PEP503_NORMALIZE = Pattern.compile("[-_.]+", Pattern.CASE_INSENSITIVE);

    /**
     * Extracts a version from a distribution filename by taking the segment that starts with the first '-' followed by a digit and continues up to the next '-'.
     */
    private static final Pattern VERSION_FROM_FILENAME = Pattern.compile("-(\\d[^-]*?)(?:-|\\.(?:tar\\.gz|tar\\.bz2|tar\\.xz|tgz|zip|whl|tar))$", Pattern.CASE_INSENSITIVE);

    PypiMetaAnalyzer() {
        this.baseUrl = DEFAULT_BASE_URL;
    }

    /**
     * {@inheritDoc}
     */
    public boolean isApplicable(final Component component) {
        return component.getPurl() != null && PackageURL.StandardTypes.PYPI.equals(component.getPurl().getType());
    }

    /**
     * {@inheritDoc}
     */
    public RepositoryType supportedRepositoryType() {
        return RepositoryType.PYPI;
    }

    /**
     * {@inheritDoc}
     */
    public MetaModel analyze(final Component component) {
        final MetaModel meta = new MetaModel(component);
        if (component.getPurl() == null) {
            return meta;
        }

        final String projectName = component.getPurl().getName();
        if (projectName == null || projectName.isEmpty()) {
            return meta;
        }

        final String normalizedName = normalizePep503(projectName);

        final String simpleBaseUrl = baseUrl.endsWith("/simple")
                ? baseUrl
                : baseUrl + "/simple";

        final String url = String.format(
                Locale.ROOT,
                simpleBaseUrl + "/%s/",
                urlEncode(normalizedName)
        );

        try (final CloseableHttpResponse response = processHttpRequest(url, ACCEPT_SIMPLE_API)) {
            if (response == null) {
                return meta;
            }

            final int status = response.getStatusLine().getStatusCode();
            if (status != HttpStatus.SC_OK) {
                handleUnexpectedHttpResponse(LOGGER, url, status, response.getStatusLine().getReasonPhrase(), component);
                return meta;
            }

            final var entity = response.getEntity();
            if (entity == null) {
                return meta;
            }

            final String body = EntityUtils.toString(entity);
            final ContentType ct = ContentType.getOrDefault(entity);
            final String mimeType = ct.getMimeType() != null ? ct.getMimeType().toLowerCase(Locale.ROOT) : "";
            final String fullContentType = response.getFirstHeader(HttpHeaders.CONTENT_TYPE) != null
                    ? response.getFirstHeader(HttpHeaders.CONTENT_TYPE).getValue().toLowerCase(Locale.ROOT)
                    : mimeType;

            // PEP 691 uses "application/vnd.pypi.simple.v1+json".
            // Some repositories may return application/json with the same structure.
            if (fullContentType.contains("json")) {
                parseSimpleJson(body, meta);
            } else if (fullContentType.contains("html")) {
                parseSimpleHtml(body, meta);
            } else {
                // Only parse what the PEPs specify.
                LOGGER.warn("Unsupported Content-Type for PyPI Simple API response: " + fullContentType);
            }

        } catch (IOException e) {
            handleRequestException(LOGGER, e);
        } catch (Exception ex) {
            throw new MetaAnalyzerException(ex);
        }

        return meta;
    }

    private static String normalizePep503(final String name) {
        final String lower = name.toLowerCase(Locale.ROOT);
        return PEP503_NORMALIZE.matcher(lower).replaceAll("-");
    }

    private static void parseSimpleJson(final String body, final MetaModel meta) {
        final JSONObject root = new JSONObject(body);

        final JSONArray files = root.optJSONArray("files");
        final JSONArray versionsArray = root.optJSONArray("versions");

        final Set<String> allVersions = new HashSet<>();
        final Set<String> nonYankedVersions = new HashSet<>();
        final Map<String, Date> earliestUploadByVersion = new HashMap<>();

        // Collect versions from the PEP 700 field, if present.
        if (versionsArray != null) {
            for (int i = 0; i < versionsArray.length(); i++) {
                final String v = versionsArray.optString(i, null);
                if (v != null && !v.isEmpty()) {
                    allVersions.add(v);
                }
            }
        }

        // Collect versions and yanked/upload-time information from files.
        if (files != null) {
            for (int i = 0; i < files.length(); i++) {
                final JSONObject file = files.optJSONObject(i);
                if (file == null) {
                    continue;
                }
                final String filename = file.optString("filename", null);
                if (filename == null) {
                    continue;
                }
                final String v = extractVersionFromFilename(filename);
                if (v == null) {
                    continue;
                }

                allVersions.add(v);

                final boolean yanked = file.optBoolean("yanked", false);
                if (!yanked) {
                    nonYankedVersions.add(v);
                }

                final String uploadTime = file.optString("upload-time", null);
                final Date parsedUpload = parseIsoInstant(uploadTime);
                if (parsedUpload != null) {
                    earliestUploadByVersion.merge(v, parsedUpload, (a, b) -> a.before(b) ? a : b);
                }
            }
        }

        if (allVersions.isEmpty()) {
            return;
        }

        // Prefer non-yanked versions unless all available versions are yanked.
        final List<String> candidates = new ArrayList<>();
        if (!nonYankedVersions.isEmpty()) {
            candidates.addAll(nonYankedVersions);
        } else {
            candidates.addAll(allVersions);
        }

        final String latest = selectLatestVersion(candidates);
        if (latest != null) {
            meta.setLatestVersion(latest);
            final Date published = earliestUploadByVersion.get(latest);
            if (published != null) {
                meta.setPublishedTimestamp(published);
            }
        }
    }

    private static void parseSimpleHtml(final String body, final MetaModel meta) {
        final Document doc = Jsoup.parse(body);
        final Elements links = doc.select("a[href]");

        final Set<String> allVersions = new HashSet<>();
        final Set<String> nonYankedVersions = new HashSet<>();

        for (final Element link : links) {
            // PEP 503: anchor text SHOULD be the filename.
            final String filename = link.text();
            final String v = extractVersionFromFilename(filename);
            if (v == null) {
                continue;
            }

            allVersions.add(v);

            // PEP 592 yanking: data-yanked attribute indicates yanked.
            final boolean yanked = link.hasAttr("data-yanked");
            if (!yanked) {
                nonYankedVersions.add(v);
            }
        }

        if (allVersions.isEmpty()) {
            return;
        }

        final List<String> candidates = new ArrayList<>();
        if (!nonYankedVersions.isEmpty()) {
            candidates.addAll(nonYankedVersions);
        } else {
            candidates.addAll(allVersions);
        }

        final String latest = selectLatestVersion(candidates);
        if (latest != null) {
            meta.setLatestVersion(latest);
        }
        // PEP 503: provides no standardized timestamp fields.
    }

    private static String extractVersionFromFilename(final String filename) {
        if (filename == null) {
            return null;
        }
        final Matcher m = VERSION_FROM_FILENAME.matcher(filename);
        if (!m.find()) {
            return null;
        }
        final String v = m.group(1);
        return (v == null || v.isEmpty()) ? null : v;
    }

    private static String selectLatestVersion(final List<String> versions) {
        if (versions == null || versions.isEmpty()) {
            return null;
        }

        return versions.stream()
                .filter(Objects::nonNull)
                .max(Comparator.comparing(ComparableVersion::new))
                .orElse(null);
    }

    private static Date parseIsoInstant(final String value) {
        if (value == null || value.isEmpty()) {
            return null;
        }
        try {
            return Date.from(Instant.parse(value));
        } catch (DateTimeParseException ex) {
            return null;
        }
    }
}


