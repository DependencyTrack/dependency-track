/*
 * This file is part of Dependency-Track.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Copyright (c) Steve Springett. All Rights Reserved.
 */
package org.owasp.dependencytrack.tasks.repositories;

import alpine.logging.Logger;
import com.github.packageurl.PackageURL;
import org.apache.http.HttpEntity;
import org.apache.http.StatusLine;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpUriRequest;
import org.owasp.dependencycheck.utils.XmlUtils;
import org.owasp.dependencytrack.model.Component;
import org.owasp.dependencytrack.util.DateUtil;
import org.owasp.dependencytrack.util.HttpClientFactory;
import org.w3c.dom.Document;
import org.xml.sax.SAXException;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;
import java.io.IOException;
import java.util.List;
import java.util.stream.Collectors;

/**
 * An IMetaAnalyzer implementation that supports Maven repositories (including Maven Central).
 *
 * @author Steve Springett
 * @since 3.1.0
 */
public class NexusMetaAnalyzer implements IMetaAnalyzer {

    private static final Logger LOGGER = Logger.getLogger(NexusMetaAnalyzer.class);
    private static final String REPO_METADATA_URL = "http://central.maven.org/maven2/%s/maven-metadata.xml";

    /**
     * {@inheritDoc}
     */
    public boolean isApplicable(Component component) {
        return component.getPurl() != null && PackageURL.StandardTypes.MAVEN.equals(component.getPurl().getType());
    }

    /**
     * {@inheritDoc}
     */
    public List<MetaModel> analyze(List<Component> components) {
        return components.stream().map(this::analyze).collect(Collectors.toList());
    }

    /**
     * {@inheritDoc}
     */
    public MetaModel analyze(Component component) {
        HttpClient httpClient = HttpClientFactory.createClient();
        MetaModel meta = new MetaModel(component);
        if (component.getPurl() != null) {
            final String mavenGavUrl = component.getPurl().getNamespace().replaceAll("\\.", "/") + "/" + component.getPurl().getName().replaceAll("\\.", "/");
            final String url = String.format(REPO_METADATA_URL, mavenGavUrl);
            try {
                HttpUriRequest request = new HttpGet(url);
                org.apache.http.HttpResponse response = httpClient.execute(request);
                StatusLine status = response.getStatusLine();
                if (status.getStatusCode() == 200) {
                    HttpEntity entity = response.getEntity();
                    if (entity != null) {
                        final Document document = XmlUtils.buildSecureDocumentBuilder().parse(entity.getContent());
                        XPathFactory xpathFactory = XPathFactory.newInstance();
                        XPath xpath = xpathFactory.newXPath();

                        XPathExpression latestExpression = xpath.compile("/metadata/versioning/latest");
                        String latest = (String)latestExpression.evaluate(document, XPathConstants.STRING);

                        XPathExpression lastUpdatedExpression = xpath.compile("/metadata/versioning/lastUpdated");
                        String lastUpdated = (String)lastUpdatedExpression.evaluate(document, XPathConstants.STRING);

                        meta.setLatestVersion(latest);
                        if (lastUpdated != null) {
                            meta.setPublishedTimestamp(DateUtil.parseDate(lastUpdated));
                        }
                    }
                } else {
                    LOGGER.debug("HTTP Status : " + response.getStatusLine().getStatusCode() + " " + response.getStatusLine().getReasonPhrase());
                    LOGGER.debug(" - Repository URL : " + url);
                    LOGGER.debug(" - Package URL : " + component.getPurl().canonicalize());
                }

            } catch (IOException | ParserConfigurationException | SAXException | XPathExpressionException e) {
                LOGGER.error("Request failure", e);
            }
        }
        return meta;
    }

}
