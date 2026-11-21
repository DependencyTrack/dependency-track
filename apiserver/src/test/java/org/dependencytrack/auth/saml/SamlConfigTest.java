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

import io.smallrye.config.SmallRyeConfigBuilder;
import org.eclipse.microprofile.config.Config;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalStateException;

class SamlConfigTest {

    private static Map<String, String> validProperties() {
        final var properties = new HashMap<String, String>();
        properties.put("dt.saml.enabled", "true");
        properties.put("dt.saml.sp.entity-id", "https://dtrack.example.com");
        properties.put("dt.saml.sp.acs-url", "https://dtrack-api.example.com/api/v2/saml/acs");
        properties.put("dt.frontend-url", "https://dtrack.example.com");
        properties.put("dt.saml.idp.metadata-url", "https://idp.example.com/saml/metadata");
        return properties;
    }

    private static Config config(Map<String, String> properties) {
        return new SmallRyeConfigBuilder().withDefaultValues(properties).build();
    }

    @Test
    void shouldBeEmptyWhenDisabled() {
        assertThat(SamlConfig.load(config(Map.of()))).isEmpty();
    }

    @Test
    void shouldLoadHttpsMetadataUrl() {
        assertThat(SamlConfig.load(config(validProperties())))
                .hasValueSatisfying(config -> assertThat(config.idpMetadataUrl())
                        .isEqualTo(URI.create("https://idp.example.com/saml/metadata")));
    }

    @Test
    void shouldRefuseHttpMetadataUrl() {
        final Map<String, String> properties = validProperties();
        properties.put("dt.saml.idp.metadata-url", "http://idp.example.com/saml/metadata");

        assertThatIllegalStateException()
                .isThrownBy(() -> SamlConfig.load(config(properties)))
                .withMessage("dt.saml.idp.metadata-url must be an https URL");
    }

    @Test
    void shouldAllowHttpForAcsAndFrontendUrl() {
        // Behind a reverse proxy, or in tests, plain HTTP is a legitimate choice for URLs that browsers visit.
        final Map<String, String> properties = validProperties();
        properties.put("dt.saml.sp.acs-url", "http://dtrack.test/api/v2/saml/acs");
        properties.put("dt.frontend-url", "http://dtrack.test");

        assertThat(SamlConfig.load(config(properties))).isPresent();
    }
}
