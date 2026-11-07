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
import org.w3c.dom.NodeList;

import javax.xml.crypto.KeySelector;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import java.net.URI;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.dependencytrack.auth.saml.SamlXml.NS_ASSERTION;
import static org.dependencytrack.auth.saml.SamlXml.NS_DSIG;
import static org.dependencytrack.auth.saml.SamlXml.NS_PROTOCOL;
import static org.dependencytrack.auth.saml.SamlXml.attribute;
import static org.dependencytrack.auth.saml.SamlXml.childElement;
import static org.dependencytrack.auth.saml.SamlXml.childElements;
import static org.dependencytrack.auth.saml.SamlXml.isElement;
import static org.dependencytrack.auth.saml.SamlXml.requireChildElement;

/// Verifies SAML 2.0 responses received via the HTTP-POST binding.
///
/// Only the profile that Dependency-Track needs is supported: a response to an authentication request
/// of Dependency-Track, with exactly one unencrypted assertion, signed on the response, the assertion, or both.
/// See ADR 044 for the reasoning behind each check.
///
/// @since 5.3.0
public final class SamlResponseValidator {

    static final Duration CLOCK_SKEW = Duration.ofSeconds(60);
    static final int MAX_RESPONSE_BYTES = 256 * 1024;

    private static final String STATUS_SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success";
    private static final String CONFIRMATION_METHOD_BEARER = "urn:oasis:names:tc:SAML:2.0:cm:bearer";
    private static final String NAME_ID_FORMAT_ENTITY = "urn:oasis:names:tc:SAML:2.0:nameid-format:entity";
    private static final Set<String> ALLOWED_CANONICALIZATION_METHODS =
            Set.of(CanonicalizationMethod.EXCLUSIVE, CanonicalizationMethod.EXCLUSIVE_WITH_COMMENTS);
    private static final Set<String> ALLOWED_TRANSFORMS = Set.of(
            Transform.ENVELOPED, CanonicalizationMethod.EXCLUSIVE, CanonicalizationMethod.EXCLUSIVE_WITH_COMMENTS);

    /// The data of a verified assertion.
    ///
    /// @param inResponseTo ID of the authentication request that the response answers.
    /// @param nameId Value of the subject's `NameID`.
    /// @param attributes Values of the assertion's attributes, by attribute name.
    public record ValidatedAssertion(String inResponseTo, String nameId, Map<String, List<String>> attributes) {

        public ValidatedAssertion {
            attributes = Map.copyOf(attributes);
        }

        public List<String> attributeValues(String name) {
            return attributes.getOrDefault(name, List.of());
        }
    }

    private final String spEntityId;
    private final String acsUrl;
    private final Clock clock;

    SamlResponseValidator(String spEntityId, URI acsUrl, Clock clock) {
        this.spEntityId = spEntityId;
        this.acsUrl = acsUrl.toString();
        this.clock = clock;
    }

    public SamlResponseValidator(SamlConfig config) {
        this(config.spEntityId(), config.acsUrl(), Clock.systemUTC());
    }

    /// Verifies a response and returns the data of its assertion.
    ///
    /// The caller must still check that [ValidatedAssertion#inResponseTo()] refers to a pending request.
    ///
    /// @param encodedResponse The Base64-encoded `SAMLResponse` form parameter.
    /// @throws SamlException When the response is refused.
    public ValidatedAssertion validate(String encodedResponse, SamlIdpMetadata idp) throws SamlException {
        final Document document = SamlXml.parse(decode(encodedResponse));

        final Element response = document.getDocumentElement();
        if (!isElement(response, NS_PROTOCOL, "Response")) {
            throw new SamlException("Root element is not a Response");
        }
        requireVersion(response);
        final String responseId = requireAttribute(response, "ID");

        // Read data only from elements whose position is checked here.
        // Anything else in the document could have been inserted by an attacker.
        if (document.getElementsByTagNameNS(NS_ASSERTION, "EncryptedAssertion").getLength() > 0) {
            throw new SamlException("Encrypted assertions are not supported");
        }
        if (document.getElementsByTagNameNS(NS_ASSERTION, "Assertion").getLength() != 1) {
            throw new SamlException("Document must contain exactly one assertion");
        }
        final Element assertion = requireChildElement(response, NS_ASSERTION, "Assertion");
        requireVersion(assertion);
        final String assertionId = requireAttribute(assertion, "ID");
        requireUniqueIds(document);

        final Element responseSignature = childElement(response, NS_DSIG, "Signature");
        final Element assertionSignature = childElement(assertion, NS_DSIG, "Signature");
        if (responseSignature == null && assertionSignature == null) {
            throw new SamlException("Neither response nor assertion is signed");
        }
        if (responseSignature != null) {
            verifySignature(responseSignature, responseId, response, assertion, idp.signingCertificates());
        }
        if (assertionSignature != null) {
            verifySignature(assertionSignature, assertionId, response, assertion, idp.signingCertificates());
        }

        final Instant now = clock.instant();
        final String inResponseTo = validateResponse(response, responseSignature != null, idp);
        final String nameId = validateAssertion(assertion, inResponseTo, idp, now);

        return new ValidatedAssertion(inResponseTo, nameId, readAttributes(assertion));
    }

    private static byte[] decode(String encodedResponse) throws SamlException {
        if (encodedResponse.length() > MAX_RESPONSE_BYTES * 4 / 3 + 4096) {
            throw new SamlException("Response is too large");
        }
        try {
            return Base64.getMimeDecoder().decode(encodedResponse);
        } catch (IllegalArgumentException e) {
            throw new SamlException("Response is not valid Base64", e);
        }
    }

    private static void requireUniqueIds(Document document) throws SamlException {
        final NodeList elements = document.getElementsByTagName("*");
        final var ids = new HashSet<String>();
        for (int i = 0; i < elements.getLength(); i++) {
            final String id = attribute((Element) elements.item(i), "ID");
            if (id != null && !ids.add(id)) {
                throw new SamlException("Duplicate ID " + id);
            }
        }
    }

    private static void verifySignature(
            Element signatureElement,
            String signedElementId,
            Element response,
            Element assertion,
            List<X509Certificate> certificates)
            throws SamlException {
        final XMLSignatureFactory factory = XMLSignatureFactory.getInstance("DOM");

        for (final X509Certificate certificate : certificates) {
            // Only trust keys from the metadata. Keys in the message's KeyInfo are ignored.
            final var context = new DOMValidateContext(
                    KeySelector.singletonKeySelector(certificate.getPublicKey()), signatureElement);
            context.setProperty("org.jcp.xml.dsig.secureValidation", Boolean.TRUE);
            context.setIdAttributeNS(response, null, "ID");
            context.setIdAttributeNS(assertion, null, "ID");

            try {
                final XMLSignature signature = factory.unmarshalXMLSignature(context);
                checkSignedInfo(signature.getSignedInfo(), signedElementId);
                if (signature.validate(context)) {
                    return;
                }
            } catch (MarshalException | XMLSignatureException e) {
                throw new SamlException("Signature of element %s is invalid".formatted(signedElementId), e);
            }
        }

        throw new SamlException(
                "Signature of element %s does not verify with any IdP certificate".formatted(signedElementId));
    }

    private static void checkSignedInfo(SignedInfo signedInfo, String signedElementId) throws SamlException {
        if (!ALLOWED_CANONICALIZATION_METHODS.contains(
                signedInfo.getCanonicalizationMethod().getAlgorithm())) {
            throw new SamlException("Canonicalization method %s is not allowed"
                    .formatted(signedInfo.getCanonicalizationMethod().getAlgorithm()));
        }

        final List<?> references = signedInfo.getReferences();
        if (references.size() != 1) {
            throw new SamlException("Signature must have exactly one reference, but has " + references.size());
        }

        // The signature must sign the element that it sits in, and nothing else.
        final Reference reference = (Reference) references.getFirst();
        if (!("#" + signedElementId).equals(reference.getURI())) {
            throw new SamlException("Signature reference %s does not point to its parent element %s"
                    .formatted(reference.getURI(), signedElementId));
        }

        boolean enveloped = false;
        for (final Object transformObject : reference.getTransforms()) {
            final String algorithm = ((Transform) transformObject).getAlgorithm();
            if (!ALLOWED_TRANSFORMS.contains(algorithm)) {
                throw new SamlException("Transform %s is not allowed".formatted(algorithm));
            }
            enveloped |= Transform.ENVELOPED.equals(algorithm);
        }
        if (!enveloped) {
            throw new SamlException("Signature is not an enveloped signature");
        }
    }

    private String validateResponse(Element response, boolean signed, SamlIdpMetadata idp) throws SamlException {
        final String destination = attribute(response, "Destination");
        if (destination == null && signed) {
            throw new SamlException("Signed response has no Destination");
        }
        if (destination != null && !acsUrl.equals(destination)) {
            throw new SamlException("Destination %s does not match ACS URL".formatted(destination));
        }

        final Element issuer = childElement(response, NS_ASSERTION, "Issuer");
        if (issuer != null) {
            requireIssuer(issuer, idp);
        }

        final Element status = requireChildElement(response, NS_PROTOCOL, "Status");
        final Element statusCode = requireChildElement(status, NS_PROTOCOL, "StatusCode");
        final String statusValue = attribute(statusCode, "Value");
        if (!STATUS_SUCCESS.equals(statusValue)) {
            throw new SamlException("Response status is %s".formatted(statusValue));
        }

        return requireAttribute(response, "InResponseTo");
    }

    private String validateAssertion(Element assertion, String inResponseTo, SamlIdpMetadata idp, Instant now)
            throws SamlException {
        requireIssuer(requireChildElement(assertion, NS_ASSERTION, "Issuer"), idp);

        final Element subject = requireChildElement(assertion, NS_ASSERTION, "Subject");
        final Element nameIdElement = requireChildElement(subject, NS_ASSERTION, "NameID");
        final String nameId = nameIdElement.getTextContent().strip();
        if (nameId.isEmpty()) {
            throw new SamlException("NameID is empty");
        }

        boolean confirmed = false;
        for (final Element confirmation : childElements(subject, NS_ASSERTION, "SubjectConfirmation")) {
            if (isValidBearerConfirmation(confirmation, inResponseTo, now)) {
                confirmed = true;
                break;
            }
        }
        if (!confirmed) {
            throw new SamlException("Assertion has no valid bearer subject confirmation");
        }

        final Element conditions = requireChildElement(assertion, NS_ASSERTION, "Conditions");
        checkTimeWindow(conditions, now);
        final List<Element> audienceRestrictions = childElements(conditions, NS_ASSERTION, "AudienceRestriction");
        if (audienceRestrictions.isEmpty()) {
            throw new SamlException("Assertion has no audience restriction");
        }
        for (final Element audienceRestriction : audienceRestrictions) {
            final boolean matches = childElements(audienceRestriction, NS_ASSERTION, "Audience").stream()
                    .anyMatch(audience ->
                            spEntityId.equals(audience.getTextContent().strip()));
            if (!matches) {
                throw new SamlException("Audience restriction does not include %s".formatted(spEntityId));
            }
        }

        if (childElements(assertion, NS_ASSERTION, "AuthnStatement").isEmpty()) {
            throw new SamlException("Assertion has no authentication statement");
        }

        return nameId;
    }

    private boolean isValidBearerConfirmation(Element confirmation, String inResponseTo, Instant now)
            throws SamlException {
        if (!CONFIRMATION_METHOD_BEARER.equals(attribute(confirmation, "Method"))) {
            return false;
        }

        final Element data = childElement(confirmation, NS_ASSERTION, "SubjectConfirmationData");
        if (data == null) {
            return false;
        }
        if (!acsUrl.equals(attribute(data, "Recipient"))) {
            return false;
        }

        final String dataInResponseTo = attribute(data, "InResponseTo");
        if (dataInResponseTo != null && !dataInResponseTo.equals(inResponseTo)) {
            return false;
        }

        final Instant notOnOrAfter = parseInstant(attribute(data, "NotOnOrAfter"));
        if (notOnOrAfter == null || !now.isBefore(notOnOrAfter.plus(CLOCK_SKEW))) {
            return false;
        }
        final Instant notBefore = parseInstant(attribute(data, "NotBefore"));
        return notBefore == null || !now.plus(CLOCK_SKEW).isBefore(notBefore);
    }

    private static void checkTimeWindow(Element conditions, Instant now) throws SamlException {
        final Instant notBefore = parseInstant(attribute(conditions, "NotBefore"));
        if (notBefore != null && now.plus(CLOCK_SKEW).isBefore(notBefore)) {
            throw new SamlException("Assertion is not yet valid");
        }
        final Instant notOnOrAfter = parseInstant(attribute(conditions, "NotOnOrAfter"));
        if (notOnOrAfter != null && !now.isBefore(notOnOrAfter.plus(CLOCK_SKEW))) {
            throw new SamlException("Assertion has expired");
        }
    }

    private static Map<String, List<String>> readAttributes(Element assertion) throws SamlException {
        final var attributes = new LinkedHashMap<String, List<String>>();
        for (final Element statement : childElements(assertion, NS_ASSERTION, "AttributeStatement")) {
            for (final Element attribute : childElements(statement, NS_ASSERTION, "Attribute")) {
                final String name = attribute(attribute, "Name");
                if (name == null || name.isBlank()) {
                    throw new SamlException("Attribute without name");
                }
                final List<String> values = attributes.computeIfAbsent(name, ignored -> new ArrayList<>());
                for (final Element value : childElements(attribute, NS_ASSERTION, "AttributeValue")) {
                    final String text = value.getTextContent();
                    if (!text.isBlank()) {
                        values.add(text);
                    }
                }
            }
        }
        attributes.replaceAll((name, values) -> List.copyOf(values));
        return attributes;
    }

    private static void requireIssuer(Element issuer, SamlIdpMetadata idp) throws SamlException {
        final String format = attribute(issuer, "Format");
        if (format != null && !NAME_ID_FORMAT_ENTITY.equals(format)) {
            throw new SamlException("Issuer has unexpected format %s".formatted(format));
        }
        final String value = issuer.getTextContent().strip();
        if (!idp.entityId().equals(value)) {
            throw new SamlException("Issuer %s does not match IdP entity ID".formatted(value));
        }
    }

    private static void requireVersion(Element element) throws SamlException {
        if (!"2.0".equals(attribute(element, "Version"))) {
            throw new SamlException("%s has unsupported version".formatted(element.getLocalName()));
        }
    }

    private static String requireAttribute(Element element, String name) throws SamlException {
        final String value = attribute(element, name);
        if (value == null || value.isBlank()) {
            throw new SamlException("%s has no %s".formatted(element.getLocalName(), name));
        }
        return value;
    }

    private static @Nullable Instant parseInstant(@Nullable String value) throws SamlException {
        if (value == null) {
            return null;
        }
        try {
            return OffsetDateTime.parse(value).toInstant();
        } catch (DateTimeParseException e) {
            throw new SamlException("Invalid timestamp %s".formatted(value), e);
        }
    }
}
