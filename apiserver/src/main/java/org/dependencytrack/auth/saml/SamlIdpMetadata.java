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

import org.w3c.dom.Document;
import org.w3c.dom.Element;

import java.io.ByteArrayInputStream;
import java.net.URI;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import static org.dependencytrack.auth.saml.SamlXml.NS_DSIG;
import static org.dependencytrack.auth.saml.SamlXml.NS_METADATA;
import static org.dependencytrack.auth.saml.SamlXml.attribute;
import static org.dependencytrack.auth.saml.SamlXml.childElements;
import static org.dependencytrack.auth.saml.SamlXml.isElement;

/// The parts of an identity provider's SAML metadata that the service provider needs.
///
/// @param entityId The IdP's entity ID, which must match the issuer of responses.
/// @param singleSignOnUrl The URL to send authentication requests to, using the HTTP-Redirect binding.
/// @param signingCertificates The certificates whose keys may sign responses and assertions.
/// @since 5.3.0
public record SamlIdpMetadata(String entityId, URI singleSignOnUrl, List<X509Certificate> signingCertificates) {

    public SamlIdpMetadata {
        signingCertificates = List.copyOf(signingCertificates);
    }

    static SamlIdpMetadata parse(byte[] xml) throws SamlException {
        final Document document = SamlXml.parse(xml);
        final Element root = document.getDocumentElement();

        final Element entityDescriptor;
        if (isElement(root, NS_METADATA, "EntityDescriptor")) {
            entityDescriptor = root;
        } else if (isElement(root, NS_METADATA, "EntitiesDescriptor")) {
            entityDescriptor = childElements(root, NS_METADATA, "EntityDescriptor").stream()
                    .filter(candidate -> !childElements(candidate, NS_METADATA, "IDPSSODescriptor")
                            .isEmpty())
                    .findFirst()
                    .orElseThrow(() -> new SamlException("Metadata contains no identity provider"));
        } else {
            throw new SamlException("Metadata root element is neither EntityDescriptor nor EntitiesDescriptor");
        }

        final String entityId = attribute(entityDescriptor, "entityID");
        if (entityId == null || entityId.isBlank()) {
            throw new SamlException("Metadata has no entityID");
        }

        final List<Element> idpDescriptors = childElements(entityDescriptor, NS_METADATA, "IDPSSODescriptor");
        if (idpDescriptors.size() != 1) {
            throw new SamlException("Expected exactly one IDPSSODescriptor, but found " + idpDescriptors.size());
        }
        final Element idpDescriptor = idpDescriptors.getFirst();

        final URI singleSignOnUrl = childElements(idpDescriptor, NS_METADATA, "SingleSignOnService").stream()
                .filter(service -> SamlXml.BINDING_HTTP_REDIRECT.equals(attribute(service, "Binding")))
                .map(service -> attribute(service, "Location"))
                .filter(location -> location != null && !location.isBlank())
                .map(URI::create)
                .findFirst()
                .orElseThrow(() -> new SamlException("Metadata has no SingleSignOnService with HTTP-Redirect binding"));

        final var certificates = new ArrayList<X509Certificate>();
        for (final Element keyDescriptor : childElements(idpDescriptor, NS_METADATA, "KeyDescriptor")) {
            final String use = attribute(keyDescriptor, "use");
            if (use != null && !"signing".equals(use)) {
                continue;
            }
            for (final Element keyInfo : childElements(keyDescriptor, NS_DSIG, "KeyInfo")) {
                for (final Element x509Data : childElements(keyInfo, NS_DSIG, "X509Data")) {
                    for (final Element certificate : childElements(x509Data, NS_DSIG, "X509Certificate")) {
                        certificates.add(parseCertificate(certificate.getTextContent()));
                    }
                }
            }
        }
        if (certificates.isEmpty()) {
            throw new SamlException("Metadata has no signing certificate");
        }

        return new SamlIdpMetadata(entityId, singleSignOnUrl, certificates);
    }

    private static X509Certificate parseCertificate(String base64) throws SamlException {
        try {
            final byte[] der = Base64.getMimeDecoder().decode(base64.strip());
            return (X509Certificate)
                    CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(der));
        } catch (IllegalArgumentException | CertificateException e) {
            throw new SamlException("Metadata contains an invalid certificate", e);
        }
    }
}
