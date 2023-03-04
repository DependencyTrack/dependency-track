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
 * Copyright (c) Steve Springett. All Rights Reserved.
 */
package org.dependencytrack.tasks.repositories;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;
import org.apache.http.HttpEntity;
import org.apache.http.HttpStatus;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.RepositoryType;
import org.dependencytrack.util.ComponentVersion;
import org.dependencytrack.util.DateUtil;
import org.dependencytrack.util.XmlUtil;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;
import com.github.packageurl.PackageURL;
import alpine.common.logging.Logger;

/**
 * An IMetaAnalyzer implementation that supports Maven repositories (including Maven Central).
 *
 * @author Steve Springett
 * @since 3.1.0
 */
public class MavenMetaAnalyzer extends AbstractMetaAnalyzer {

    private static final Logger LOGGER = Logger.getLogger(MavenMetaAnalyzer.class);
    private static final String DEFAULT_BASE_URL = "https://repo1.maven.org/maven2";
    private static final String REPO_METADATA_URL = "/%s/maven-metadata.xml";

    MavenMetaAnalyzer() {
        this.baseUrl = DEFAULT_BASE_URL;
    }

    /**
     * {@inheritDoc}
     */
    public boolean isApplicable(final Component component) {
        return component.getPurl() != null && PackageURL.StandardTypes.MAVEN.equals(component.getPurl().getType());
    }

    /**
     * {@inheritDoc}
     */
    public RepositoryType supportedRepositoryType() {
        return RepositoryType.MAVEN;
    }

    /**
     * {@inheritDoc}
     */
    public MetaModel analyze(final Component component) {
        final MetaModel meta = new MetaModel(component);
        if (component.getPurl() != null) {
            final String mavenGavUrl = component.getPurl().getNamespace().replace(".", "/") + "/" + component.getPurl().getName();
            final String url = String.format(baseUrl + REPO_METADATA_URL, mavenGavUrl);
            try (final CloseableHttpResponse response = processHttpRequest(url)) {
                if (response.getStatusLine().getStatusCode() == HttpStatus.SC_OK) {
                    final HttpEntity entity = response.getEntity();
                    if (entity != null) {
                        try (InputStream in = entity.getContent()) {
                            analyzeContent(meta, in);
                        }
                    }
                } else {
                    handleUnexpectedHttpResponse(LOGGER, url, response.getStatusLine().getStatusCode(), response.getStatusLine().getReasonPhrase(), component);
                }
            } catch (IOException | ParserConfigurationException | SAXException | XPathExpressionException e) {
                handleRequestException(LOGGER, e);
            }

        }
        return meta;
    }

    /**
     * The maven-metadata.xml files are not updated by Nexus during deployment, they are updated by Maven. It downloads the file, updates it, and then redeploys it.
     *
     * Maven will update the "release" field only during the following scenarios:
     *
     * 1. Maven 2.x deploys using -DupdateReleaseInfo=true
     * 2. Maven 3.x deploys a non-snapshot artifact
     *
     * The "latest" field is only intended for plugin resolution, and is only set upon deployment of a maven-plugin artifact, both for Maven 2.x and 3.x regardless whether a release or snapshot gets deployed.
     *
     * Also, Maven will update these fields with whatever version it is currently deploying, so "latest" and "release" will not necessarily correspond to the highest version number.
     *
     * https://support.sonatype.com/hc/en-us/articles/213464638-Why-are-the-latest-and-release-tags-in-maven-metadata-xml-not-being-updated-after-deploying-artifacts-
     */
    private void analyzeContent(final MetaModel meta, InputStream in)
            throws SAXException, IOException, ParserConfigurationException, XPathExpressionException {

        final Document document = XmlUtil.buildSecureDocumentBuilder().parse(in);
        final XPathFactory xpathFactory = XPathFactory.newInstance();
        final XPath xpath = xpathFactory.newXPath();

        // latest: What the latest version in the directory is, including snapshots
        final String latest = getLatestVersionFromMetadata(document, xpath);
        // When the metadata was last updated
        final String lastUpdated = getLastUpdatedFromMetadata(document, xpath);
        // versions/version*: (Many) Versions available of the artifact (both releases and snapshots)
        final NodeList versionsList = getVersionsFromMetadata(document, xpath);

        // latest and release might not be the highest version in case of a hotfix on an older release!

        // find highest stable or unstable version from list of versions
        List<String> versions = getVersions(versionsList);
        String highestVersion = ComponentVersion.findHighestVersion(versions);
        meta.setLatestVersion(highestVersion);
        if (lastUpdated != null && highestVersion != null && highestVersion.equals(latest)) {
            // lastUpdated reflects the timestamp when latest was updated, so it's only valid when highestVersion == latest
            meta.setPublishedTimestamp(DateUtil.parseDate(lastUpdated));
        }
    }

    private NodeList getVersionsFromMetadata(final Document document, final XPath xpath) throws XPathExpressionException {
        final XPathExpression versionsExpression = xpath.compile("/metadata/versioning/versions/*");
        return (NodeList) versionsExpression.evaluate(document, XPathConstants.NODESET);
    }

    private String getLastUpdatedFromMetadata(final Document document, final XPath xpath) throws XPathExpressionException {
        final XPathExpression lastUpdatedExpression = xpath.compile("/metadata/versioning/lastUpdated");
        return (String) lastUpdatedExpression.evaluate(document, XPathConstants.STRING);
    }

    private String getLatestVersionFromMetadata(final Document document, final XPath xpath) throws XPathExpressionException {
        final XPathExpression latestExpression = xpath.compile("/metadata/versioning/latest");
        return (String) latestExpression.evaluate(document, XPathConstants.STRING);
    }

    private List<String> getVersions(final NodeList versionsList) {
        List<String> versions = new ArrayList<>();
        for (int n = 0; n < versionsList.getLength(); n++) {
            Node versionNode = versionsList.item(n);
            String version = versionNode.getFirstChild().getNodeValue().trim();
            versions.add(version);
        }
        return versions;
    }

}
