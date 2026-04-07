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
package org.dependencytrack.tasks;

import alpine.common.logging.Logger;
import alpine.persistence.Transaction;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.util.PersistenceUtil;

import javax.jdo.Query;
import java.util.Map;

/**
 * @since 4.11.0
 */
abstract class AbstractNistMirrorTask {

    private final Logger logger = Logger.getLogger(getClass());

    Vulnerability synchronizeVulnerability(final QueryManager qm, final Vulnerability vuln) {
        PersistenceUtil.assertNonPersistent(vuln, "vuln must not be persistent");

        return qm.callInTransaction(Transaction.defaultOptions().withSerializeRead(true), () -> {
            Vulnerability persistentVuln = getVulnerabilityByCveId(qm, vuln.getVulnId());
            if (persistentVuln == null) {
                persistentVuln = qm.getPersistenceManager().makePersistent(vuln);
            } else {
                final var diffs = qm.updateVulnerabilityIfChanged(persistentVuln, vuln);
                if (!diffs.isEmpty()) {
                    logger.debug("%s has changed: %s".formatted(vuln.getVulnId(), diffs));
                    return persistentVuln;
                }

                logger.debug("%s has not changed".formatted(vuln.getVulnId()));
            }

            return persistentVuln;
        });
    }

    /**
     * Get a {@link Vulnerability} by its CVE ID (implying the source {@link Vulnerability.Source#NVD}).
     * <p>
     * It differs from {@link QueryManager#getVulnerabilityByVulnId(String, String)} in that it does not fetch any
     * adjacent relationships (e.g. affected components and aliases).
     *
     * @param qm    The {@link QueryManager} to use
     * @param cveId The CVE ID to look for
     * @return The {@link Vulnerability} matching the CVE ID, or {@code null} when no match was found
     */
    private static Vulnerability getVulnerabilityByCveId(final QueryManager qm, final String cveId) {
        final Query<Vulnerability> query = qm.getPersistenceManager().newQuery(Vulnerability.class);
        query.setFilter("source == :source && vulnId == :cveId");
        query.setNamedParameters(Map.of(
                "source", Vulnerability.Source.NVD.name(),
                "cveId", cveId
        ));
        try {
            return query.executeUnique();
        } finally {
            query.closeAll();
        }
    }

}
