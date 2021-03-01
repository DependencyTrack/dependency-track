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
package org.dependencytrack.persistence;

import alpine.logging.Logger;
import org.w3c.dom.Document;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;
import java.io.IOException;
import java.io.InputStream;
import java.util.Map;
import java.util.TreeMap;

/**
 * This class parses CWEs and adds them to the database (if necessary).
 * cwec_v3.3.xml obtained from https://cwe.mitre.org/data/xml/cwec_v3.3.xml
 *
 * @author Steve Springett
 * @since 3.0.0
 */
public class CweImporter {

    private static final Logger LOGGER = Logger.getLogger(CweImporter.class);
    private static final Map<Integer, String> CWE_MAPPINGS = new TreeMap<>();

    public void processCweDefinitions() throws ParserConfigurationException, SAXException, IOException, XPathExpressionException {
        try (QueryManager qm = new QueryManager();
                InputStream is = Thread.currentThread().getContextClassLoader().getResourceAsStream("nist/cwec_v4.3.xml")) {

            LOGGER.info("Synchronizing CWEs with datastore");

            final DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
            factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
            factory.setXIncludeAware(false);
            factory.setExpandEntityReferences(false);
            final DocumentBuilder builder = factory.newDocumentBuilder();

            final Document doc = builder.parse(is);
            final XPathFactory xPathfactory = XPathFactory.newInstance();
            final XPath xpath = xPathfactory.newXPath();

            final XPathExpression expr1 = xpath.compile("/Weakness_Catalog/Categories/Category");
            final XPathExpression expr2 = xpath.compile("/Weakness_Catalog/Weaknesses/Weakness");
            final XPathExpression expr3 = xpath.compile("/Weakness_Catalog/Views/View");

            parseNodes((NodeList) expr1.evaluate(doc, XPathConstants.NODESET));
            parseNodes((NodeList) expr2.evaluate(doc, XPathConstants.NODESET));
            parseNodes((NodeList) expr3.evaluate(doc, XPathConstants.NODESET));

            for (final Map.Entry<Integer, String> entry : CWE_MAPPINGS.entrySet()) {
                qm.createCweIfNotExist(entry.getKey(), entry.getValue().replaceAll("\\\\", "\\\\\\\\"));
            }
            LOGGER.info("CWE synchronization complete");
        }
    }

    private static void parseNodes(final NodeList nodeList) {
        for (int i = 0; i < nodeList.getLength(); i++) {
            final Node node = nodeList.item(i);
            final NamedNodeMap attributes = node.getAttributes();
            final Integer id = Integer.valueOf(attributes.getNamedItem("ID").getNodeValue());
            final String desc = attributes.getNamedItem("Name").getNodeValue();
            CWE_MAPPINGS.put(id, desc);
        }
    }

}
