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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.HexFormat;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;

import static org.dependencytrack.auth.saml.SamlXml.escapeAttribute;

/// Creates the SAML messages that the service provider sends.
///
/// @since 5.3.0
public final class SamlMessages {

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    /// An authentication request, ready to be sent via the HTTP-Redirect binding.
    ///
    /// @param id The request ID, which the response must refer to with `InResponseTo`.
    /// @param redirectUrl The URL of the IdP, including the encoded request.
    public record AuthnRequest(String id, URI redirectUrl) {}

    private SamlMessages() {}

    public static AuthnRequest createAuthnRequest(SamlConfig config, SamlIdpMetadata idp, Instant now) {
        final byte[] idBytes = new byte[20];
        SECURE_RANDOM.nextBytes(idBytes);
        // IDs must be valid XML names, so they must not start with a digit.
        final String id = "_" + HexFormat.of().formatHex(idBytes);

        final String xml = """
                <samlp:AuthnRequest xmlns:samlp="%s" xmlns:saml="%s" ID="%s" Version="2.0" IssueInstant="%s" \
                Destination="%s" AssertionConsumerServiceURL="%s" ProtocolBinding="%s">\
                <saml:Issuer>%s</saml:Issuer>\
                <samlp:NameIDPolicy AllowCreate="true"/>\
                </samlp:AuthnRequest>""".formatted(
                        SamlXml.NS_PROTOCOL,
                        SamlXml.NS_ASSERTION,
                        id,
                        now.truncatedTo(ChronoUnit.SECONDS),
                        escapeAttribute(idp.singleSignOnUrl().toString()),
                        escapeAttribute(config.acsUrl().toString()),
                        SamlXml.BINDING_HTTP_POST,
                        escapeAttribute(config.spEntityId()));

        final String encoded = Base64.getEncoder().encodeToString(deflate(xml.getBytes(StandardCharsets.UTF_8)));
        final String ssoUrl = idp.singleSignOnUrl().toString();
        final String separator = ssoUrl.contains("?") ? "&" : "?";

        return new AuthnRequest(
                id,
                URI.create(ssoUrl + separator + "SAMLRequest=" + URLEncoder.encode(encoded, StandardCharsets.UTF_8)));
    }

    /// Creates the SAML metadata of the service provider, for administrators to upload to the IdP.
    public static String createServiceProviderMetadata(SamlConfig config) {
        return """
                <?xml version="1.0" encoding="UTF-8"?>
                <md:EntityDescriptor xmlns:md="%s" entityID="%s">
                  <md:SPSSODescriptor AuthnRequestsSigned="false" WantAssertionsSigned="true" \
                protocolSupportEnumeration="%s">
                    <md:AssertionConsumerService Binding="%s" Location="%s" index="0" isDefault="true"/>
                  </md:SPSSODescriptor>
                </md:EntityDescriptor>
                """.formatted(
                        SamlXml.NS_METADATA,
                        escapeAttribute(config.spEntityId()),
                        SamlXml.NS_PROTOCOL,
                        SamlXml.BINDING_HTTP_POST,
                        escapeAttribute(config.acsUrl().toString()));
    }

    // The HTTP-Redirect binding requires raw DEFLATE, without zlib header.
    private static byte[] deflate(byte[] data) {
        final var out = new ByteArrayOutputStream();
        final var deflater = new Deflater(Deflater.DEFLATED, /* nowrap */ true);
        try (final var deflaterOut = new DeflaterOutputStream(out, deflater)) {
            deflaterOut.write(data);
        } catch (IOException e) {
            throw new IllegalStateException(e);
        } finally {
            deflater.end();
        }
        return out.toByteArray();
    }
}
