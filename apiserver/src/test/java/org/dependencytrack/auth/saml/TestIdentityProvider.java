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
import org.w3c.dom.Node;

import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.StringWriter;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import java.util.zip.DataFormatException;
import java.util.zip.Inflater;

/// A SAML identity provider for tests. Creates and signs responses with keys from a test keystore.
public final class TestIdentityProvider {

    public static final String ENTITY_ID = "https://idp.example.com/saml";
    public static final URI SSO_URL = URI.create("https://idp.example.com/saml/sso");
    public static final String SP_ENTITY_ID = "https://dtrack.example.com";
    public static final URI ACS_URL = URI.create("https://dtrack-api.example.com/api/v2/saml/acs");

    public record Key(PrivateKey privateKey, X509Certificate certificate) {}

    public static final Key IDP_KEY = loadKey("idp");
    public static final Key ATTACKER_KEY = loadKey("attacker");

    /// The parameters of a response. Defaults describe a valid response.
    public static final class ResponseSpec {
        public String responseId = "_response1";
        public String assertionId = "_assertion1";
        public String inResponseTo = "_request1";
        public String issuer = ENTITY_ID;
        public String destination = ACS_URL.toString();
        public String recipient = ACS_URL.toString();
        public String audience = SP_ENTITY_ID;
        public String status = "urn:oasis:names:tc:SAML:2.0:status:Success";
        public String nameId = "jane.doe@example.com";
        public Instant issueInstant = Instant.now();
        public Duration lifetime = Duration.ofMinutes(5);
        public Map<String, List<String>> attributes = new LinkedHashMap<>();

        public ResponseSpec attribute(String name, String... values) {
            attributes.put(name, List.of(values));
            return this;
        }
    }

    private TestIdentityProvider() {}

    public static SamlIdpMetadata metadata() {
        return new SamlIdpMetadata(ENTITY_ID, SSO_URL, List.of(IDP_KEY.certificate()));
    }

    public static String metadataXml() {
        try {
            final String certificate =
                    Base64.getEncoder().encodeToString(IDP_KEY.certificate().getEncoded());
            return """
                    <md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="%s">
                      <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
                        <md:KeyDescriptor use="signing">
                          <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
                            <ds:X509Data><ds:X509Certificate>%s</ds:X509Certificate></ds:X509Data>
                          </ds:KeyInfo>
                        </md:KeyDescriptor>
                        <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" \
                    Location="https://idp.example.com/saml/post"/>
                        <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" \
                    Location="%s"/>
                      </md:IDPSSODescriptor>
                    </md:EntityDescriptor>
                    """.formatted(ENTITY_ID, certificate, SSO_URL);
        } catch (java.security.cert.CertificateEncodingException e) {
            throw new IllegalStateException(e);
        }
    }

    public static String responseXml(ResponseSpec spec) {
        final Instant notOnOrAfter = spec.issueInstant.plus(spec.lifetime);
        final var attributes = new StringBuilder();
        if (!spec.attributes.isEmpty()) {
            attributes.append("<saml:AttributeStatement>");
            spec.attributes.forEach((name, values) -> {
                attributes.append("<saml:Attribute Name=\"").append(name).append("\">");
                values.forEach(value ->
                        attributes.append("<saml:AttributeValue>").append(value).append("</saml:AttributeValue>"));
                attributes.append("</saml:Attribute>");
            });
            attributes.append("</saml:AttributeStatement>");
        }

        return """
                <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" \
                xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="%1$s" Version="2.0" IssueInstant="%2$s" \
                Destination="%3$s" InResponseTo="%4$s">\
                <saml:Issuer>%5$s</saml:Issuer>\
                <samlp:Status><samlp:StatusCode Value="%6$s"/></samlp:Status>\
                <saml:Assertion ID="%7$s" Version="2.0" IssueInstant="%2$s">\
                <saml:Issuer>%5$s</saml:Issuer>\
                <saml:Subject>\
                <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">%8$s</saml:NameID>\
                <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">\
                <saml:SubjectConfirmationData InResponseTo="%4$s" NotOnOrAfter="%9$s" Recipient="%10$s"/>\
                </saml:SubjectConfirmation>\
                </saml:Subject>\
                <saml:Conditions NotBefore="%2$s" NotOnOrAfter="%9$s">\
                <saml:AudienceRestriction><saml:Audience>%11$s</saml:Audience></saml:AudienceRestriction>\
                </saml:Conditions>\
                <saml:AuthnStatement AuthnInstant="%2$s">\
                <saml:AuthnContext>\
                <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef>\
                </saml:AuthnContext>\
                </saml:AuthnStatement>\
                %12$s\
                </saml:Assertion>\
                </samlp:Response>""".formatted(
                        spec.responseId,
                        spec.issueInstant,
                        spec.destination,
                        spec.inResponseTo,
                        spec.issuer,
                        spec.status,
                        spec.assertionId,
                        spec.nameId,
                        notOnOrAfter,
                        spec.recipient,
                        spec.audience,
                        attributes);
    }

    public static Document parse(String xml) {
        try {
            final var factory = DocumentBuilderFactory.newInstance();
            factory.setNamespaceAware(true);
            return factory.newDocumentBuilder().parse(new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    public static Element response(Document document) {
        return document.getDocumentElement();
    }

    public static Element assertion(Document document) {
        return (Element) document.getElementsByTagNameNS(SamlXml.NS_ASSERTION, "Assertion")
                .item(0);
    }

    /// Signs an element with an enveloped signature, placed after its `Issuer` child.
    public static void sign(Element element, Key key) {
        sign(element, element, key);
    }

    /// Signs `signed`, placing the signature into `container`.
    public static void sign(Element signed, Element container, Key key) {
        try {
            final XMLSignatureFactory factory = XMLSignatureFactory.getInstance("DOM");
            final Reference reference = factory.newReference(
                    "#" + signed.getAttribute("ID"),
                    factory.newDigestMethod(DigestMethod.SHA256, null),
                    List.of(
                            factory.newTransform(Transform.ENVELOPED, (TransformParameterSpec) null),
                            factory.newTransform(CanonicalizationMethod.EXCLUSIVE, (TransformParameterSpec) null)),
                    null,
                    null);
            final SignedInfo signedInfo = factory.newSignedInfo(
                    factory.newCanonicalizationMethod(CanonicalizationMethod.EXCLUSIVE, (C14NMethodParameterSpec) null),
                    factory.newSignatureMethod(SignatureMethod.RSA_SHA256, null),
                    List.of(reference));
            final KeyInfoFactory keyInfoFactory = factory.getKeyInfoFactory();
            final KeyInfo keyInfo =
                    keyInfoFactory.newKeyInfo(List.of(keyInfoFactory.newX509Data(List.of(key.certificate()))));

            final Node issuer = container
                    .getElementsByTagNameNS(SamlXml.NS_ASSERTION, "Issuer")
                    .item(0);
            final Node nextSibling = issuer != null && issuer.getParentNode() == container
                    ? issuer.getNextSibling()
                    : container.getFirstChild();
            final var context = new DOMSignContext(key.privateKey(), container, nextSibling);
            context.setIdAttributeNS(signed, null, "ID");
            factory.newXMLSignature(signedInfo, keyInfo).sign(context);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    public static String serialize(Document document) {
        try {
            final var transformer = TransformerFactory.newInstance().newTransformer();
            transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
            transformer.setOutputProperty(OutputKeys.INDENT, "no");
            final var writer = new StringWriter();
            transformer.transform(new DOMSource(document), new StreamResult(writer));
            return writer.toString();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    public static String encode(String xml) {
        return Base64.getEncoder().encodeToString(xml.getBytes(StandardCharsets.UTF_8));
    }

    public static String encode(Document document) {
        return encode(serialize(document));
    }

    /// Creates a response with a signed assertion, optionally modified before signing.
    public static String signedAssertionResponse(ResponseSpec spec, Consumer<Document> beforeSigning) {
        final Document document = parse(responseXml(spec));
        beforeSigning.accept(document);
        sign(assertion(document), IDP_KEY);
        return encode(document);
    }

    public static String signedAssertionResponse(ResponseSpec spec) {
        return signedAssertionResponse(spec, document -> {});
    }

    public static String codeChallenge(String verifier) {
        try {
            return Base64.getUrlEncoder()
                    .withoutPadding()
                    .encodeToString(
                            MessageDigest.getInstance("SHA-256").digest(verifier.getBytes(StandardCharsets.US_ASCII)));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    /// Decodes the authentication request from a URL of the HTTP-Redirect binding.
    public static Element decodeAuthnRequest(URI identityProviderUrl) {
        final String query = identityProviderUrl.getRawQuery();
        final String encoded = URLDecoder.decode(query.substring("SAMLRequest=".length()), StandardCharsets.UTF_8);
        final var inflater = new Inflater(/* nowrap */ true);
        inflater.setInput(Base64.getDecoder().decode(encoded));
        final var out = new ByteArrayOutputStream();
        final byte[] buffer = new byte[1024];
        try {
            while (!inflater.finished()) {
                out.write(buffer, 0, inflater.inflate(buffer));
            }
        } catch (DataFormatException e) {
            throw new IllegalStateException(e);
        } finally {
            inflater.end();
        }
        return parse(out.toString(StandardCharsets.UTF_8)).getDocumentElement();
    }

    private static Key loadKey(String alias) {
        try (final InputStream in = TestIdentityProvider.class.getResourceAsStream("/saml/test-keystore.p12")) {
            final KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(in, "changeit".toCharArray());
            return new Key((PrivateKey) keyStore.getKey(alias, "changeit".toCharArray()), (X509Certificate)
                    keyStore.getCertificate(alias));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
