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
package org.dependencytrack.vulndatasource.jvn;

import org.jspecify.annotations.Nullable;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

/**
 * Parses the XML returned by the MyJVN {@code getVulnDetailInfo} API into a {@link JvnAdvisory}.
 * <p>
 * Uses namespace-agnostic local-name matching, since the VULDEF document mixes several XML
 * namespaces ({@code vuldef}, {@code sec}, {@code marking}, ...).
 *
 * @since 5.1.0
 */
final class JvnDetailParser {

    private static final Pattern CVE_ID = Pattern.compile("CVE-\\d{4}-\\d{4,}");
    private static final Pattern CWE_ID = Pattern.compile("CWE-(\\d+)");

    private JvnDetailParser() {
    }

    static List<JvnAdvisory> parse(final byte[] xml) {
        return parse(new ByteArrayInputStream(xml));
    }

    static List<JvnAdvisory> parse(final InputStream xml) {
        final Document document = parseDocument(xml);
        final var advisories = new ArrayList<JvnAdvisory>();
        for (final Element vulinfo : childElementsByLocalName(document.getDocumentElement(), "Vulinfo")) {
            final JvnAdvisory advisory = parseVulinfo(vulinfo);
            if (advisory != null) {
                advisories.add(advisory);
            }
        }
        return advisories;
    }

    private static @Nullable JvnAdvisory parseVulinfo(final Element vulinfo) {
        final String jvnDbId = firstText(vulinfo, "VulinfoID");
        if (jvnDbId == null || jvnDbId.isBlank()) {
            return null;
        }

        final Element data = firstElement(vulinfo, "VulinfoData");
        final String title = data != null ? firstText(data, "Title") : null;
        // <Overview> is nested inside <VulinfoData><VulinfoDescription>, not a direct child of
        // VulinfoData, so it must be located via a descendant search (not firstText).
        final String overview = data != null ? firstDescendantText(data, "Overview") : null;
        // <Impact><ImpactItem><Description> is the detailed impact text (rendered as the UI's
        // "Details" field); <Solution><SolutionItem><Description> is the countermeasure (the UI's
        // "Recommendation"). Navigate the section explicitly so the unrelated <HistoryItem>
        // <Description> is not picked up.
        final String detail = data != null ? joinItemDescriptions(data, "Impact", "ImpactItem") : null;
        final String recommendation =
                data != null ? joinItemDescriptions(data, "Solution", "SolutionItem") : null;

        final var cveIds = new ArrayList<String>();
        final var cweIds = new ArrayList<Integer>();
        final var referenceUrls = new ArrayList<String>();
        for (final Element related : descendantsByLocalName(vulinfo, "RelatedItem")) {
            final String id = firstText(related, "VulinfoID");
            // CWE weaknesses are carried as <RelatedItem type="cwe"> whose VulinfoID is e.g.
            // "CWE-78". Collect the numeric id, and skip its <URL> — a JVN CWE glossary link, not
            // an advisory reference.
            final Integer cwe = parseCweId(id);
            if ("cwe".equalsIgnoreCase(attr(related, "type")) || cwe != null) {
                if (cwe != null && !cweIds.contains(cwe)) {
                    cweIds.add(cwe);
                }
                continue;
            }
            if (id != null && CVE_ID.matcher(id).matches() && !cveIds.contains(id)) {
                cveIds.add(id);
            }
            final String url = firstText(related, "URL");
            if (url != null && !url.isBlank() && !referenceUrls.contains(url)) {
                referenceUrls.add(url);
            }
        }

        final var affected = new ArrayList<JvnAdvisory.AffectedProduct>();
        for (final Element item : descendantsByLocalName(vulinfo, "AffectedItem")) {
            final String cpe = firstText(item, "Cpe");
            if (cpe == null || cpe.isBlank()) {
                continue;
            }
            final var versionTexts = new ArrayList<String>();
            for (final Element vn : childElementsByLocalName(item, "VersionNumber")) {
                final String text = textOf(vn);
                if (text != null && !text.isBlank()) {
                    versionTexts.add(text.trim());
                }
            }
            affected.add(new JvnAdvisory.AffectedProduct(
                    firstText(item, "Name"),
                    firstText(item, "ProductName"),
                    cpe.trim(),
                    List.copyOf(versionTexts)));
        }

        final var cvssList = new ArrayList<JvnAdvisory.Cvss>();
        for (final Element cvss : descendantsByLocalName(vulinfo, "Cvss")) {
            cvssList.add(new JvnAdvisory.Cvss(
                    attr(cvss, "version"),
                    firstText(cvss, "Severity"),
                    parseDouble(firstText(cvss, "Base")),
                    firstText(cvss, "Vector")));
        }

        return new JvnAdvisory(
                jvnDbId.trim(),
                title,
                overview,
                detail,
                recommendation,
                List.copyOf(cveIds),
                List.copyOf(cweIds),
                List.copyOf(cvssList),
                List.copyOf(affected),
                List.copyOf(referenceUrls),
                parseInstant(firstDescendantText(vulinfo, "DatePublic")),
                parseInstant(firstDescendantText(vulinfo, "DateLastUpdated")));
    }

    // ---- DOM helpers (namespace-agnostic) ----

    private static Document parseDocument(final InputStream xml) {
        try {
            final DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            factory.setNamespaceAware(true);
            factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
            factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
            final DocumentBuilder builder = factory.newDocumentBuilder();
            final Document document = builder.parse(new InputSource(xml));
            document.getDocumentElement().normalize();
            return document;
        } catch (Exception e) {
            throw new IllegalArgumentException("Failed to parse JVN detail XML", e);
        }
    }

    private static List<Element> childElementsByLocalName(final Element parent, final String localName) {
        final var result = new ArrayList<Element>();
        final NodeList children = parent.getChildNodes();
        for (int i = 0; i < children.getLength(); i++) {
            final Node node = children.item(i);
            if (node.getNodeType() == Node.ELEMENT_NODE && localName.equals(node.getLocalName())) {
                result.add((Element) node);
            }
        }
        return result;
    }

    private static List<Element> descendantsByLocalName(final Element parent, final String localName) {
        final var result = new ArrayList<Element>();
        collectDescendants(parent, localName, result);
        return result;
    }

    private static void collectDescendants(final Element parent, final String localName, final List<Element> out) {
        final NodeList children = parent.getChildNodes();
        for (int i = 0; i < children.getLength(); i++) {
            final Node node = children.item(i);
            if (node.getNodeType() != Node.ELEMENT_NODE) {
                continue;
            }
            final Element element = (Element) node;
            if (localName.equals(element.getLocalName())) {
                out.add(element);
            }
            collectDescendants(element, localName, out);
        }
    }

    private static @Nullable Element firstElement(final Element parent, final String localName) {
        final List<Element> elements = childElementsByLocalName(parent, localName);
        return elements.isEmpty() ? null : elements.getFirst();
    }

    private static @Nullable String firstText(final Element parent, final String localName) {
        final List<Element> direct = childElementsByLocalName(parent, localName);
        if (!direct.isEmpty()) {
            return textOf(direct.getFirst());
        }
        return null;
    }

    private static @Nullable String firstDescendantText(final Element parent, final String localName) {
        final List<Element> descendants = descendantsByLocalName(parent, localName);
        return descendants.isEmpty() ? null : textOf(descendants.getFirst());
    }

    private static @Nullable String textOf(final @Nullable Element element) {
        if (element == null) {
            return null;
        }
        final String text = element.getTextContent();
        return text == null ? null : text.trim();
    }

    private static @Nullable String attr(final Element element, final String name) {
        final String value = element.getAttribute(name);
        return value == null || value.isBlank() ? null : value;
    }

    /**
     * Joins the {@code <Description>} texts of every {@code <itemLocalName>} under the
     * {@code <sectionLocalName>} child of {@code data} (e.g. Impact/ImpactItem or
     * Solution/SolutionItem), or {@code null} if the section is absent or carries no description.
     */
    private static @Nullable String joinItemDescriptions(
            final Element data, final String sectionLocalName, final String itemLocalName) {
        final Element section = firstElement(data, sectionLocalName);
        if (section == null) {
            return null;
        }
        final var parts = new ArrayList<String>();
        for (final Element item : childElementsByLocalName(section, itemLocalName)) {
            final String description = firstText(item, "Description");
            if (description != null && !description.isBlank() && !parts.contains(description)) {
                parts.add(description);
            }
        }
        return parts.isEmpty() ? null : String.join("\n\n", parts);
    }

    private static @Nullable Integer parseCweId(final @Nullable String value) {
        if (value == null) {
            return null;
        }
        final var matcher = CWE_ID.matcher(value.trim());
        if (!matcher.matches()) {
            return null;
        }
        try {
            return Integer.valueOf(matcher.group(1));
        } catch (NumberFormatException e) {
            return null;
        }
    }

    private static @Nullable Double parseDouble(final @Nullable String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        try {
            return Double.parseDouble(value.trim());
        } catch (NumberFormatException e) {
            return null;
        }
    }

    private static @Nullable Instant parseInstant(final @Nullable String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        try {
            return OffsetDateTime.parse(value.trim()).toInstant();
        } catch (DateTimeParseException e) {
            return null;
        }
    }

    static byte[] bytes(final String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }
}
