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
package org.dependencytrack.upgrade.v4145;

import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.model.VulnerableSoftware;
import org.junit.jupiter.api.Test;

import javax.jdo.datastore.JDOConnection;
import java.sql.Connection;

import static org.assertj.core.api.Assertions.assertThat;

class v4145UpdaterTest extends PersistenceCapableTest {

    @Test
    void shouldNormalizePypiPurlNames() throws Exception {
        final VulnerableSoftware dotted = createVulnerableSoftware("pypi", "zope.interface");
        final VulnerableSoftware underscored = createVulnerableSoftware("pypi", "zope_interface");
        final VulnerableSoftware repeated = createVulnerableSoftware("pypi", "chartkit.-core");
        final VulnerableSoftware normalized = createVulnerableSoftware("pypi", "chartkit-core");
        final VulnerableSoftware nonPypi = createVulnerableSoftware("npm", "foo.bar");

        final JDOConnection jdoConnection = qm.getPersistenceManager().getDataStoreConnection();
        try {
            new v4145Updater().executeUpgrade(qm, (Connection) jdoConnection.getNativeConnection());
        } finally {
            jdoConnection.close();
        }

        qm.getPersistenceManager().refreshAll(dotted, underscored, repeated, normalized, nonPypi);
        assertThat(dotted.getPurlName()).isEqualTo("zope-interface");
        assertThat(underscored.getPurlName()).isEqualTo("zope-interface");
        assertThat(repeated.getPurlName()).isEqualTo("chartkit-core");
        assertThat(normalized.getPurlName()).isEqualTo("chartkit-core");
        assertThat(nonPypi.getPurlName()).isEqualTo("foo.bar");
    }

    private VulnerableSoftware createVulnerableSoftware(final String purlType, final String purlName) {
        final var vs = new VulnerableSoftware();
        vs.setPurlType(purlType);
        vs.setPurlName(purlName);
        vs.setVulnerable(true);
        return qm.persist(vs);
    }

}
