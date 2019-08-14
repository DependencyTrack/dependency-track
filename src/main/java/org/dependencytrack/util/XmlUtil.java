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
package org.dependencytrack.util;

import org.xml.sax.SAXException;
import org.xml.sax.SAXNotRecognizedException;
import org.xml.sax.SAXNotSupportedException;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;
import java.io.InputStream;

import static org.apache.xerces.jaxp.JAXPConstants.JAXP_SCHEMA_LANGUAGE;
import static org.apache.xerces.jaxp.JAXPConstants.JAXP_SCHEMA_SOURCE;
import static org.apache.xerces.jaxp.JAXPConstants.W3C_XML_SCHEMA;

public final class XmlUtil {

    private XmlUtil() { }

    /**
     * Constructs a validating secure SAX Parser.
     *
     * @param schemaStream One or more inputStreams with the schema(s) that the
     * parser should be able to validate the XML against, one InputStream per
     * schema
     * @return a SAX Parser
     * @throws javax.xml.parsers.ParserConfigurationException is thrown if there
     * is a parser configuration exception
     * @throws org.xml.sax.SAXNotRecognizedException thrown if there is an
     * unrecognized feature
     * @throws org.xml.sax.SAXNotSupportedException thrown if there is a
     * non-supported feature
     * @throws org.xml.sax.SAXException is thrown if there is a
     * org.xml.sax.SAXException
     */
    public static SAXParser buildSecureSaxParser(InputStream... schemaStream) throws ParserConfigurationException,
            SAXNotRecognizedException, SAXNotSupportedException, SAXException {
        final SAXParserFactory factory = SAXParserFactory.newInstance();
        factory.setNamespaceAware(true);
        factory.setValidating(true);
        factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
        factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        factory.setFeature("http://apache.org/xml/features/nonvalidating/load-dtd-grammar", false);
        factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
        System.setProperty("javax.xml.accessExternalSchema", "file, https");

        final SAXParser saxParser = factory.newSAXParser();
        saxParser.setProperty(JAXP_SCHEMA_LANGUAGE, W3C_XML_SCHEMA);
        saxParser.setProperty(JAXP_SCHEMA_SOURCE, schemaStream);
        return saxParser;
    }

    /**
     * Constructs a secure SAX Parser.
     *
     * @return a SAX Parser
     * @throws javax.xml.parsers.ParserConfigurationException thrown if there is
     * a parser configuration exception
     * @throws org.xml.sax.SAXNotRecognizedException thrown if there is an
     * unrecognized feature
     * @throws org.xml.sax.SAXNotSupportedException thrown if there is a
     * non-supported feature
     * @throws org.xml.sax.SAXException is thrown if there is a
     * org.xml.sax.SAXException
     */
    public static SAXParser buildSecureSaxParser() throws ParserConfigurationException,
            SAXNotRecognizedException, SAXNotSupportedException, SAXException {
        final SAXParserFactory factory = SAXParserFactory.newInstance();
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
        factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        return factory.newSAXParser();
    }

    /**
     * Constructs a new document builder with security features enabled.
     *
     * @return a new document builder
     * @throws javax.xml.parsers.ParserConfigurationException thrown if there is
     * a parser configuration exception
     */
    public static DocumentBuilder buildSecureDocumentBuilder() throws ParserConfigurationException {
        final DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
        factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        return factory.newDocumentBuilder();
    }
}
