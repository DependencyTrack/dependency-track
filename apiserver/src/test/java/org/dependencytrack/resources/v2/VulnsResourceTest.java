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
package org.dependencytrack.resources.v2;

import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import io.smallrye.config.SmallRyeConfigBuilder;
import org.dependencytrack.JerseyTestExtension;
import org.dependencytrack.ResourceTest;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.cache.api.NoopCacheManager;
import org.dependencytrack.kevdatasource.api.KevAssertion;
import org.dependencytrack.kevdatasource.api.KevDataSource;
import org.dependencytrack.kevdatasource.api.KevDataSourceFactory;
import org.dependencytrack.model.Severity;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.VulnerabilityKey;
import org.dependencytrack.persistence.jdbi.JdbiFactory;
import org.dependencytrack.persistence.jdbi.KevDao;
import org.dependencytrack.persistence.jdbi.VulnerabilityAliasDao;
import org.dependencytrack.plugin.api.ServiceRegistry;
import org.dependencytrack.plugin.runtime.PluginManager;
import org.dependencytrack.secret.TestSecretManager;
import org.dependencytrack.secret.management.SecretManager;
import org.glassfish.jersey.inject.hk2.AbstractBinder;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import jakarta.ws.rs.core.Response;

import java.net.http.HttpClient;
import java.time.Instant;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.Set;

import static net.javacrumbs.jsonunit.assertj.JsonAssertions.assertThatJson;
import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.useJdbiTransaction;

class VulnsResourceTest extends ResourceTest {

    private static SecretManager secretManager;
    private static PluginManager pluginManager;

    @RegisterExtension
    static JerseyTestExtension jersey = new JerseyTestExtension(new ResourceConfig().register(new AbstractBinder() {
        @Override
        protected void configure() {
            bindFactory(() -> pluginManager).to(PluginManager.class);
        }
    }));

    @BeforeAll
    static void beforeAll() {
        secretManager = new TestSecretManager();
    }

    @BeforeEach
    void beforeEach() {
        pluginManager = new PluginManager(
                new SmallRyeConfigBuilder().build(),
                new NoopCacheManager(),
                secretManager::getSecretValue,
                JdbiFactory.createJdbi(),
                HttpClient.newHttpClient(),
                List.of(KevDataSource.class));
    }

    @AfterEach
    void afterEach() {
        if (pluginManager != null) {
            pluginManager.close();
        }
    }

    @Test
    void listVulnerabilityKevAssertionsShouldListKevAssertionsIncludingThoseOfAliases() {
        pluginManager.loadPlugins(List.of(() -> List.of(new DummyKevDataSourceFactory())));

        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);

        var cve = new Vulnerability();
        cve.setVulnId("CVE-2021-44228");
        cve.setSource(Vulnerability.Source.NVD);
        cve.setSeverity(Severity.CRITICAL);
        qm.createVulnerability(cve);

        var ghsa = new Vulnerability();
        ghsa.setVulnId("GHSA-jfh8-c2jp-5v3q");
        ghsa.setSource(Vulnerability.Source.GITHUB);
        ghsa.setSeverity(Severity.CRITICAL);
        qm.createVulnerability(ghsa);

        useJdbiTransaction(handle -> {
            new VulnerabilityAliasDao(handle)
                    .syncAssertions(
                            "TEST",
                            new VulnerabilityKey("CVE-2021-44228", Vulnerability.Source.NVD),
                            Set.of(new VulnerabilityKey("GHSA-jfh8-c2jp-5v3q", Vulnerability.Source.GITHUB)));

            final var kevDao = handle.attach(KevDao.class);
            kevDao.upsertBatch(
                    "dummy-kev-data-source",
                    List.of(new KevAssertion(
                            "NVD",
                            "CVE-2021-44228",
                            Instant.parse("2021-12-10T00:00:00Z"),
                            "Apply updates",
                            true,
                            "Log4Shell",
                            JsonNodeFactory.instance.objectNode().put("cveID", "CVE-2021-44228"))));
            kevDao.upsertBatch(
                    "unregistered-kev-data-source",
                    List.of(new KevAssertion(
                            "GITHUB",
                            "GHSA-jfh8-c2jp-5v3q",
                            null,
                            null,
                            null,
                            null,
                            JsonNodeFactory.instance.objectNode())));
        });

        final Response response = jersey.target("/vulns/GITHUB/GHSA-jfh8-c2jp-5v3q/kev-assertions")
                .request()
                .header(X_API_KEY, apiKey)
                .get();

        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "items": [
                    {
                      "asserter": "unregistered-kev-data-source",
                      "asserter_display_name": "unregistered-kev-data-source",
                      "vuln_source": "GITHUB",
                      "vuln_id": "GHSA-jfh8-c2jp-5v3q",
                      "created_at": "${json-unit.any-number}",
                      "updated_at": "${json-unit.any-number}"
                    },
                    {
                      "asserter": "dummy-kev-data-source",
                      "asserter_display_name": "Dummy KEV",
                      "vuln_source": "NVD",
                      "vuln_id": "CVE-2021-44228",
                      "published_at": 1639094400000,
                      "required_action": "Apply updates",
                      "known_ransomware": true,
                      "description": "Log4Shell",
                      "created_at": "${json-unit.any-number}",
                      "updated_at": "${json-unit.any-number}"
                    }
                  ],
                  "total": {
                    "count": 2,
                    "type": "EXACT"
                  }
                }
                """);
    }

    @Test
    void listVulnerabilityKevAssertionsShouldReturnEmptyListWhenVulnerabilityHasNoAssertions() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);

        var vuln = new Vulnerability();
        vuln.setVulnId("CVE-2022-22965");
        vuln.setSource(Vulnerability.Source.NVD);
        vuln.setSeverity(Severity.CRITICAL);
        qm.createVulnerability(vuln);

        final Response response = jersey.target("/vulns/NVD/CVE-2022-22965/kev-assertions")
                .request()
                .header(X_API_KEY, apiKey)
                .get();

        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "items": [],
                  "total": {
                    "count": 0,
                    "type": "EXACT"
                  }
                }
                """);
    }

    @Test
    void listVulnerabilityKevAssertionsShouldReturnNotFoundWhenVulnerabilityDoesNotExist() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);

        final Response response = jersey.target("/vulns/NVD/CVE-0000-0000/kev-assertions")
                .request()
                .header(X_API_KEY, apiKey)
                .get();

        assertThat(response.getStatus()).isEqualTo(404);
    }

    @Test
    void listVulnerabilityKevAssertionsShouldReturnForbiddenWithoutPermission() {
        final Response response = jersey.target("/vulns/NVD/CVE-2021-44228/kev-assertions")
                .request()
                .header(X_API_KEY, apiKey)
                .get();

        assertThat(response.getStatus()).isEqualTo(403);
    }

    private static final class DummyKevDataSource implements KevDataSource {

        @Override
        public boolean hasNext() {
            return false;
        }

        @Override
        public KevAssertion next() {
            throw new NoSuchElementException();
        }
    }

    private static final class DummyKevDataSourceFactory implements KevDataSourceFactory {

        @Override
        public @NonNull String extensionName() {
            return "dummy-kev-data-source";
        }

        @Override
        public @NonNull String displayName() {
            return "Dummy KEV";
        }

        @Override
        public @NonNull Class<? extends KevDataSource> extensionClass() {
            return DummyKevDataSource.class;
        }

        @Override
        public int priority() {
            return PRIORITY_HIGHEST;
        }

        @Override
        public void init(@NonNull ServiceRegistry serviceRegistry) {}

        @Override
        public boolean isEnabled() {
            return true;
        }

        @Override
        public @NonNull KevDataSource create() {
            throw new UnsupportedOperationException();
        }
    }
}
