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
 * Copyright (c) Steve Springett. All Rights Reserved.
 */
package org.dependencytrack.tasks;

import alpine.Config;
import alpine.event.framework.Event;
import alpine.event.framework.LoggableSubscriber;
import alpine.logging.Logger;
import alpine.notification.Notification;
import alpine.notification.NotificationLevel;
import org.dependencytrack.event.IndexEvent;
import org.dependencytrack.event.VulnDbSyncEvent;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.VulnerableSoftware;
import org.dependencytrack.notification.NotificationConstants;
import org.dependencytrack.notification.NotificationGroup;
import org.dependencytrack.notification.NotificationScope;
import org.dependencytrack.parser.vulndb.ModelConverter;
import org.dependencytrack.persistence.QueryManager;
import us.springett.parsers.cpe.Cpe;
import us.springett.parsers.cpe.CpeParser;
import us.springett.parsers.cpe.exceptions.CpeEncodingException;
import us.springett.parsers.cpe.exceptions.CpeParsingException;
import us.springett.vulndbdatamirror.parser.VulnDbParser;
import us.springett.vulndbdatamirror.parser.model.CPE;
import us.springett.vulndbdatamirror.parser.model.Product;
import us.springett.vulndbdatamirror.parser.model.Results;
import us.springett.vulndbdatamirror.parser.model.Vendor;
import us.springett.vulndbdatamirror.parser.model.Version;
import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Subscriber task that performs synchronization with VulnDB mirrored data.
 * This task relies on an existing mirror generated from vulndb-data-mirror. The mirror must exist
 * in a 'vulndb' subdirectory of the Dependency-Track data directory. i.e.  ~/dependency-track/vulndb
 *
 * https://github.com/stevespringett/vulndb-data-mirror
 *
 * @author Steve Springett
 * @since 3.0.0
 */
public class VulnDbSyncTask implements LoggableSubscriber {

    private static final Logger LOGGER = Logger.getLogger(VulnDbSyncTask.class);

    private boolean successful = true;

    /**
     * {@inheritDoc}
     */
    public void inform(final Event e) {
        if (e instanceof VulnDbSyncEvent) {
            LOGGER.info("Starting VulnDB mirror synchronization task");
            final File vulndbDir = new File(Config.getInstance().getDataDirectorty(), "vulndb");
            if (!vulndbDir.exists()) {
                LOGGER.info("VulnDB mirror directory does not exist. Skipping.");
                return;
            }
            final File[] files = vulndbDir.listFiles(
                    (dir, name) -> name.toLowerCase(Locale.ENGLISH).startsWith("vulnerabilities_")
            );
            if (files != null) {
                for (final File file : files) {
                    LOGGER.info("Parsing: " + file.getName());
                    final VulnDbParser parser = new VulnDbParser();
                    try {
                        final Results results = parser.parse(file, us.springett.vulndbdatamirror.parser.model.Vulnerability.class);
                        updateDatasource(results);
                    } catch (IOException ex) {
                        LOGGER.error("An error occurred while parsing VulnDB payload: " + file.getName(), ex);
                        successful = false;
                        Notification.dispatch(new Notification()
                                .scope(NotificationScope.SYSTEM)
                                .group(NotificationGroup.DATASOURCE_MIRRORING)
                                .title(NotificationConstants.Title.VULNDB_MIRROR)
                                .content("An error occurred parsing VulnDB payload. Check log for details. " + ex.getMessage())
                                .level(NotificationLevel.ERROR)
                        );
                    }
                }
            }
            Event.dispatch(new IndexEvent(IndexEvent.Action.COMMIT, Vulnerability.class));
            LOGGER.info("VulnDB mirror synchronization task complete");
            if (successful) {
                Notification.dispatch(new Notification()
                        .scope(NotificationScope.SYSTEM)
                        .group(NotificationGroup.DATASOURCE_MIRRORING)
                        .title(NotificationConstants.Title.VULNDB_MIRROR)
                        .content("Mirroring of VulnDB completed successfully")
                        .level(NotificationLevel.INFORMATIONAL)
                );
            }
        }
    }

    /**
     * Synchronizes the VulnDB vulnerabilities with the internal Dependency-Track database.
     * @param results the results to synchronize
     */
    private void updateDatasource(final Results results) {
        LOGGER.info("Updating datasource with VulnDB vulnerabilities");
        try (QueryManager qm = new QueryManager()) {
            for (final Object o: results.getResults()) {
                if (o instanceof us.springett.vulndbdatamirror.parser.model.Vulnerability) {
                    final us.springett.vulndbdatamirror.parser.model.Vulnerability vulnDbVuln = (us.springett.vulndbdatamirror.parser.model.Vulnerability)o;
                    final org.dependencytrack.model.Vulnerability vulnerability = ModelConverter.convert(qm, vulnDbVuln);
                    final Vulnerability synchronizeVulnerability = qm.synchronizeVulnerability(vulnerability, false);
                    final List<VulnerableSoftware> vsList = parseCpes(qm, synchronizeVulnerability, vulnDbVuln);
                    synchronizeVulnerability.setVulnerableSoftware(vsList);
                    qm.persist(synchronizeVulnerability);
                }
            }
        }
    }

    public static List<VulnerableSoftware> parseCpes(final QueryManager qm, final Vulnerability vulnerability,
                                                     final us.springett.vulndbdatamirror.parser.model.Vulnerability vulnDbVuln) {
        // cpe:2.3:a:belavier_commerce:abantecart:1.2.8:*:*:*:*:*:*:*
        final List<VulnerableSoftware> vsList = new ArrayList<>();
        if (vulnDbVuln.getVendors() != null) {
            for (Vendor vendor: vulnDbVuln.getVendors()) {
                if (vendor.getProducts() != null) {
                    for (Product product: vendor.getProducts()) {
                        if (product.getVersions() != null) {
                            for (Version version: product.getVersions()) {
                                if (version != null) {
                                    if (version.isAffected()) {
                                        if (version.getCpes() != null) {
                                            for (CPE cpeObject : version.getCpes()) {
                                                try {
                                                    final Cpe cpe = CpeParser.parse(cpeObject.getCpe(), true);
                                                    final VulnerableSoftware vs = generateVulnerableSoftware(qm, cpe, vulnerability);
                                                    if (vs != null) {
                                                        vsList.add(vs);
                                                    }
                                                } catch (CpeParsingException e) {
                                                    // Normally, this would be logged to error, however, VulnDB contains a lot of invalid CPEs
                                                    LOGGER.debug("An error occurred parsing " + cpeObject.getCpe(), e);
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        return vsList;
    }

    private static VulnerableSoftware generateVulnerableSoftware(final QueryManager qm, final Cpe cpe,
                                                                 final Vulnerability vulnerability) {
        VulnerableSoftware vs = qm.getVulnerableSoftwareByCpe23(cpe.toCpe23FS(), null, null, null, null);
        if (vs != null) {
            return vs;
        }
        try {
            vs = org.dependencytrack.parser.nvd.ModelConverter.convertCpe23UriToVulnerableSoftware(cpe.toCpe23FS());
            vs.setVulnerable(true);
            vs.addVulnerability(vulnerability);
            // VulnDB does not provide version ranges for the CPEs that exist inside Vendor->Product->Version->CPE
            vs.setVersionEndExcluding(null);
            vs.setVersionEndIncluding(null);
            vs.setVersionStartExcluding(null);
            vs.setVersionStartIncluding(null);
            vs = qm.persist(vs);
            //Event.dispatch(new IndexEvent(IndexEvent.Action.CREATE, qm.detach(VulnerableSoftware.class, vs.getId())));
            return vs;
        } catch (CpeParsingException | CpeEncodingException e) {
            LOGGER.warn("An error occurred while parsing: " + cpe.toCpe23FS() + " - The CPE is invalid and will be discarded.");
        }
        return null;
    }

}
