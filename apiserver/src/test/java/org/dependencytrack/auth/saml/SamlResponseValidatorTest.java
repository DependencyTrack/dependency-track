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

import org.dependencytrack.auth.saml.SamlResponseValidator.ValidatedAssertion;
import org.dependencytrack.auth.saml.TestIdentityProvider.ResponseSpec;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.dependencytrack.auth.saml.TestIdentityProvider.ACS_URL;
import static org.dependencytrack.auth.saml.TestIdentityProvider.ATTACKER_KEY;
import static org.dependencytrack.auth.saml.TestIdentityProvider.IDP_KEY;
import static org.dependencytrack.auth.saml.TestIdentityProvider.SP_ENTITY_ID;
import static org.dependencytrack.auth.saml.TestIdentityProvider.assertion;
import static org.dependencytrack.auth.saml.TestIdentityProvider.encode;
import static org.dependencytrack.auth.saml.TestIdentityProvider.metadata;
import static org.dependencytrack.auth.saml.TestIdentityProvider.parse;
import static org.dependencytrack.auth.saml.TestIdentityProvider.response;
import static org.dependencytrack.auth.saml.TestIdentityProvider.responseXml;
import static org.dependencytrack.auth.saml.TestIdentityProvider.sign;
import static org.dependencytrack.auth.saml.TestIdentityProvider.signedAssertionResponse;

class SamlResponseValidatorTest {

    private static final Instant NOW = Instant.parse("2026-10-28T12:00:00Z");

    private final SamlResponseValidator validator =
            new SamlResponseValidator(SP_ENTITY_ID, ACS_URL, Clock.fixed(NOW, ZoneOffset.UTC));

    private static ResponseSpec spec() {
        final var spec = new ResponseSpec();
        spec.issueInstant = NOW;
        return spec;
    }

    @Test
    void shouldAcceptResponseWithSignedAssertion() throws Exception {
        final ResponseSpec spec = spec().attribute(
                        "groups", "CONTOSO\\DT-Admins", "3f2b9c1e-8a4d-4b7e-9c2f-1d5e6a7b8c9d")
                .attribute("email", "jane.doe@example.com");

        final ValidatedAssertion assertion = validator.validate(signedAssertionResponse(spec), metadata());

        assertThat(assertion.inResponseTo()).isEqualTo("_request1");
        assertThat(assertion.nameId()).isEqualTo("jane.doe@example.com");
        assertThat(assertion.attributeValues("groups"))
                .containsExactly("CONTOSO\\DT-Admins", "3f2b9c1e-8a4d-4b7e-9c2f-1d5e6a7b8c9d");
        assertThat(assertion.attributeValues("email")).containsExactly("jane.doe@example.com");
        assertThat(assertion.attributeValues("missing")).isEmpty();
    }

    @Test
    void shouldAcceptResponseWithSignedResponse() throws Exception {
        final Document document = parse(responseXml(spec()));
        sign(response(document), IDP_KEY);

        assertThat(validator.validate(encode(document), metadata()).nameId()).isEqualTo("jane.doe@example.com");
    }

    @Test
    void shouldAcceptResponseWithSignedResponseAndAssertion() throws Exception {
        final Document document = parse(responseXml(spec()));
        sign(assertion(document), IDP_KEY);
        sign(response(document), IDP_KEY);

        assertThat(validator.validate(encode(document), metadata()).nameId()).isEqualTo("jane.doe@example.com");
    }

    @Test
    void shouldAcceptClockSkewWithinLimit() throws Exception {
        final ResponseSpec spec = spec();
        spec.issueInstant = NOW.plusSeconds(30);

        assertThat(validator.validate(signedAssertionResponse(spec), metadata()))
                .isNotNull();
    }

    @Test
    void shouldRefuseUnsignedResponse() {
        assertRefused(encode(responseXml(spec())), "Neither response nor assertion is signed");
    }

    @Test
    void shouldRefuseResponseSignedWithUnknownKey() {
        final Document document = parse(responseXml(spec()));
        sign(assertion(document), ATTACKER_KEY);

        assertRefused(encode(document), "does not verify");
    }

    @Test
    void shouldRefuseAssertionModifiedAfterSigning() {
        final Document document = parse(responseXml(spec()));
        sign(assertion(document), IDP_KEY);
        document.getElementsByTagNameNS(SamlXml.NS_ASSERTION, "NameID").item(0).setTextContent("admin");

        assertRefused(encode(document), "does not verify");
    }

    @Test
    void shouldRefuseResponseWithInvalidSignatureOnAssertionEvenWhenResponseIsSigned() {
        final Document document = parse(responseXml(spec()));
        sign(assertion(document), ATTACKER_KEY);
        sign(response(document), IDP_KEY);

        assertRefused(encode(document), "does not verify");
    }

    @Test
    void shouldRefuseSignatureWrappingWithSecondAssertion() {
        // Classic wrapping attack: keep the signed assertion in the document, where the signature still verifies,
        // and add an unsigned assertion with attacker-controlled content where the application reads it.
        final Document document = parse(responseXml(spec()));
        final Element signedAssertion = assertion(document);
        sign(signedAssertion, IDP_KEY);

        final var evilAssertion = (Element) signedAssertion.cloneNode(true);
        evilAssertion.setAttribute("ID", "_evil");
        evilAssertion
                .getElementsByTagNameNS(SamlXml.NS_ASSERTION, "NameID")
                .item(0)
                .setTextContent("admin");
        final Element extensions = document.createElementNS(SamlXml.NS_PROTOCOL, "samlp:Extensions");
        response(document).replaceChild(evilAssertion, signedAssertion);
        extensions.appendChild(signedAssertion);
        response(document)
                .insertBefore(extensions, response(document).getFirstChild().getNextSibling());

        assertRefused(encode(document), "exactly one assertion");
    }

    @Test
    void shouldRefuseSignatureWrappingWithDuplicateId() {
        // Move the signed response content aside, and reuse its ID for an attacker-controlled element.
        final Document document = parse(responseXml(spec()));
        final Element assertion = assertion(document);
        sign(assertion, IDP_KEY);

        final Element status = (Element)
                document.getElementsByTagNameNS(SamlXml.NS_PROTOCOL, "Status").item(0);
        status.setAttributeNS(null, "ID", assertion.getAttribute("ID"));

        assertRefused(encode(document), "Duplicate ID");
    }

    @Test
    void shouldRefuseSignatureThatReferencesAnotherElement() {
        // A signature in the assertion that signs the response must not count as signature of the assertion.
        final Document document = parse(responseXml(spec()));
        sign(response(document), assertion(document), IDP_KEY);

        assertRefused(encode(document), "does not point to its parent element");
    }

    @Test
    void shouldRefuseEncryptedAssertion() {
        final Document document = parse(responseXml(spec()));
        sign(assertion(document), IDP_KEY);
        response(document).appendChild(document.createElementNS(SamlXml.NS_ASSERTION, "saml:EncryptedAssertion"));

        assertRefused(encode(document), "Encrypted assertions are not supported");
    }

    @Test
    void shouldRefuseDocumentTypeDeclaration() {
        final String xml = "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>" + responseXml(spec());

        assertRefused(encode(xml), "Malformed XML");
    }

    @Test
    void shouldRefuseUnknownIssuer() {
        final ResponseSpec spec = spec();
        spec.issuer = "https://evil.example.com";

        assertRefused(signedAssertionResponse(spec), "does not match IdP entity ID");
    }

    @Test
    void shouldRefuseWrongDestination() {
        final ResponseSpec spec = spec();
        spec.destination = "https://evil.example.com/acs";

        assertRefused(signedAssertionResponse(spec), "Destination");
    }

    @Test
    void shouldRefuseWrongRecipient() {
        final ResponseSpec spec = spec();
        spec.recipient = "https://evil.example.com/acs";

        assertRefused(signedAssertionResponse(spec), "no valid bearer subject confirmation");
    }

    @Test
    void shouldRefuseWrongAudience() {
        final ResponseSpec spec = spec();
        spec.audience = "https://other-app.example.com";

        assertRefused(signedAssertionResponse(spec), "Audience restriction");
    }

    @Test
    void shouldRefuseExpiredAssertion() {
        final ResponseSpec spec = spec();
        spec.issueInstant = NOW.minus(Duration.ofMinutes(10));

        assertRefused(signedAssertionResponse(spec), "no valid bearer subject confirmation");
    }

    @Test
    void shouldRefuseAssertionThatIsNotYetValid() {
        final ResponseSpec spec = spec();
        spec.issueInstant = NOW.plus(Duration.ofMinutes(5));

        assertRefused(signedAssertionResponse(spec), "not yet valid");
    }

    @Test
    void shouldRefuseUnsuccessfulStatus() {
        final ResponseSpec spec = spec();
        spec.status = "urn:oasis:names:tc:SAML:2.0:status:Requester";

        assertRefused(signedAssertionResponse(spec), "Response status");
    }

    @Test
    void shouldRefuseMismatchingInResponseToInSubjectConfirmation() {
        final String response = signedAssertionResponse(
                spec(), document -> response(document).setAttributeNS(null, "InResponseTo", "_otherRequest"));

        assertRefused(response, "no valid bearer subject confirmation");
    }

    @Test
    void shouldRefuseMalformedBase64() {
        assertRefused("not base64!", "Base64");
    }

    private void assertRefused(String encodedResponse, String messageFragment) {
        assertThatExceptionOfType(SamlException.class)
                .isThrownBy(() -> validator.validate(encodedResponse, metadata()))
                .withMessageContaining(messageFragment);
    }
}
