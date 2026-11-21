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
package org.dependencytrack.auth.saml;

import org.jspecify.annotations.Nullable;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.xml.sax.SAXException;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/// XML helpers for SAML messages and metadata.
///
/// @since 5.3.0
final class SamlXml {

    static final String NS_PROTOCOL = "urn:oasis:names:tc:SAML:2.0:protocol";
    static final String NS_ASSERTION = "urn:oasis:names:tc:SAML:2.0:assertion";
    static final String NS_METADATA = "urn:oasis:names:tc:SAML:2.0:metadata";
    static final String NS_DSIG = "http://www.w3.org/2000/09/xmldsig#";

    static final String BINDING_HTTP_REDIRECT = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect";
    static final String BINDING_HTTP_POST = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";

    private SamlXml() {}

    /// Parses an XML document without resolving document type declarations or external entities.
    static Document parse(byte[] xml) throws SamlException {
        try {
            final DocumentBuilder builder = newDocumentBuilderFactory().newDocumentBuilder();
            builder.setErrorHandler(null);
            return builder.parse(new ByteArrayInputStream(xml));
        } catch (ParserConfigurationException e) {
            throw new IllegalStateException("Failed to create XML parser", e);
        } catch (SAXException | IOException e) {
            throw new SamlException("Malformed XML", e);
        }
    }

    private static DocumentBuilderFactory newDocumentBuilderFactory() throws ParserConfigurationException {
        final DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setNamespaceAware(true);
        factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
        factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
        factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
        factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
        factory.setXIncludeAware(false);
        factory.setExpandEntityReferences(false);
        return factory;
    }

    static boolean isElement(Node node, String namespace, String localName) {
        return node instanceof Element element
                && namespace.equals(element.getNamespaceURI())
                && localName.equals(element.getLocalName());
    }

    static List<Element> childElements(Element parent, String namespace, String localName) {
        final var children = new ArrayList<Element>();
        for (Node child = parent.getFirstChild(); child != null; child = child.getNextSibling()) {
            if (isElement(child, namespace, localName)) {
                children.add((Element) child);
            }
        }
        return children;
    }

    static @Nullable Element childElement(Element parent, String namespace, String localName) throws SamlException {
        final List<Element> children = childElements(parent, namespace, localName);
        if (children.size() > 1) {
            throw new SamlException("Expected at most one %s element in %s, but found %d"
                    .formatted(localName, parent.getLocalName(), children.size()));
        }
        return children.isEmpty() ? null : children.getFirst();
    }

    static Element requireChildElement(Element parent, String namespace, String localName) throws SamlException {
        final Element child = childElement(parent, namespace, localName);
        if (child == null) {
            throw new SamlException("Missing %s element in %s".formatted(localName, parent.getLocalName()));
        }
        return child;
    }

    /// Returns the value of an unqualified attribute, or `null` when it is absent.
    static @Nullable String attribute(Element element, String name) {
        return element.hasAttributeNS(null, name) ? element.getAttributeNS(null, name) : null;
    }

    static String escapeAttribute(String value) {
        final var sb = new StringBuilder(value.length());
        for (int i = 0; i < value.length(); i++) {
            final char c = value.charAt(i);
            switch (c) {
                case '&' -> sb.append("&amp;");
                case '<' -> sb.append("&lt;");
                case '>' -> sb.append("&gt;");
                case '"' -> sb.append("&quot;");
                case '\'' -> sb.append("&apos;");
                default -> sb.append(c);
            }
        }
        return sb.toString();
    }
}
