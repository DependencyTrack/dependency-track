/*
 * This file is part of Dependency-Track.
 *
 * Dependency-Track is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option) any
 * later version.
 *
 * Dependency-Track is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * Dependency-Track. If not, see http://www.gnu.org/licenses/.
 */
package org.owasp.dependencytrack.persistence;

import alpine.logging.Logger;
import org.w3c.dom.Document;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathFactory;
import java.io.InputStream;
import java.util.Map;
import java.util.TreeMap;

/**
 * This class parses CWEs and adds them to the database (if necessary).
 * cwec_v2.9.xml obtained from https://cwe.mitre.org/data/xml/cwec_v2.9.xml
 */
public class CweImporter {

    private static final Logger logger = Logger.getLogger(CweImporter.class);
    private static final String INDENT = "    ";
    private static final Map<Integer, String> CWE_Mappings = new TreeMap<>();

    public void processCweDefinitions() throws Exception {
        try (QueryManager qm = new QueryManager()) {
            logger.info("Syncing CWEs with datastore");

            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
            factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
            factory.setXIncludeAware(false);
            factory.setExpandEntityReferences(false);
            DocumentBuilder builder = factory.newDocumentBuilder();

            InputStream is = this.getClass().getClassLoader().getResourceAsStream("nist/cwec_v2.9.xml");
            Document doc = builder.parse(is);
            XPathFactory xPathfactory = XPathFactory.newInstance();
            XPath xpath = xPathfactory.newXPath();

            XPathExpression expr1 = xpath.compile("/Weakness_Catalog/Categories/Category");
            XPathExpression expr2 = xpath.compile("/Weakness_Catalog/Weaknesses/Weakness");
            XPathExpression expr3 = xpath.compile("/Weakness_Catalog/Compound_Elements/Compound_Element");

            parseNodes((NodeList) expr1.evaluate(doc, XPathConstants.NODESET));
            parseNodes((NodeList) expr2.evaluate(doc, XPathConstants.NODESET));
            parseNodes((NodeList) expr3.evaluate(doc, XPathConstants.NODESET));

            for (Map.Entry<Integer, String> entry : CWE_Mappings.entrySet()) {
                qm.createCweIfNotExist(entry.getKey(), entry.getValue().replaceAll("\\\\", "\\\\\\\\"));
            }
        }
    }

    private static void parseNodes(NodeList nodeList) {
        for (int i=0; i<nodeList.getLength(); i++) {
            Node node = nodeList.item(i);
            NamedNodeMap attributes = node.getAttributes();
            Integer id = Integer.valueOf(attributes.getNamedItem("ID").getNodeValue());
            String desc = attributes.getNamedItem("Name").getNodeValue();
            CWE_Mappings.put(id, desc);
        }
    }

}
