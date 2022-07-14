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
package org.dependencytrack.tasks.scanners;

import alpine.common.logging.Logger;
import alpine.event.framework.Event;
import alpine.event.framework.Subscriber;
import alpine.model.ConfigProperty;
import alpine.security.crypto.DataEncryption;
import org.dependencytrack.common.UnirestFactory;
import org.dependencytrack.event.VulnDbAnalysisEvent;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.ConfigPropertyConstants;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.parser.vulndb.ModelConverter;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.util.NotificationUtil;
import us.springett.vulndbdatamirror.client.VulnDbApi;
import us.springett.vulndbdatamirror.parser.model.Results;

import java.util.List;

/**
 * Subscriber task that performs an analysis of component using VulnDB REST API.
 *
 * @author Steve Springett
 * @since 3.6.0
 */
public class VulnDbAnalysisTask extends BaseComponentAnalyzerTask implements Subscriber {

    private static final Logger LOGGER = Logger.getLogger(VulnDbAnalysisTask.class);
    private static final String TARGET_HOST = "https://vulndb.cyberriskanalytics.com/";
    private static final int PAGE_SIZE = 100;
    private String apiConsumerKey;
    private String apiConsumerSecret;

    public AnalyzerIdentity getAnalyzerIdentity() {
        return AnalyzerIdentity.VULNDB_ANALYZER;
    }

    /**
     * {@inheritDoc}
     */
    public void inform(final Event e) {
        if (e instanceof VulnDbAnalysisEvent) {
            if (!super.isEnabled(ConfigPropertyConstants.SCANNER_VULNDB_ENABLED)) {
                return;
            }
            try (QueryManager qm = new QueryManager()) {
                final ConfigProperty apiConsumerKey = qm.getConfigProperty(
                        ConfigPropertyConstants.SCANNER_VULNDB_OAUTH1_CONSUMER_KEY.getGroupName(),
                        ConfigPropertyConstants.SCANNER_VULNDB_OAUTH1_CONSUMER_KEY.getPropertyName()
                );
                final ConfigProperty apiConsumerSecret = qm.getConfigProperty(
                        ConfigPropertyConstants.SCANNER_VULNDB_OAUTH1_CONSUMER_SECRET.getGroupName(),
                        ConfigPropertyConstants.SCANNER_VULNDB_OAUTH1_CONSUMER_SECRET.getPropertyName()
                );
                if (apiConsumerKey == null || apiConsumerKey.getPropertyValue() == null) {
                    LOGGER.warn("An OAuth 1.0a consumer key has not been specified for use with VulnDB. Skipping");
                    return;
                }
                if (apiConsumerSecret == null || apiConsumerSecret.getPropertyValue() == null) {
                    LOGGER.warn("An OAuth 1.0a consumer secret has not been specified for use with VulnDB. Skipping");
                    return;
                }
                this.apiConsumerKey = apiConsumerKey.getPropertyValue();
                try {
                    this.apiConsumerSecret = DataEncryption.decryptAsString(apiConsumerSecret.getPropertyValue());
                } catch (Exception ex) {
                    LOGGER.error("An error occurred decrypting the VulnDB consumer secret. Skipping", ex);
                    return;
                }
            }
            final VulnDbAnalysisEvent event = (VulnDbAnalysisEvent)e;
            LOGGER.info("Starting VulnDB analysis task");
            if (event.getComponents().size() > 0) {
                analyze(event.getComponents());
            }
            LOGGER.info("VulnDB analysis complete");
        }
    }

    /**
     * Determines if the {@link VulnDbAnalysisTask} is capable of analyzing the specified Component.
     *
     * @param component the Component to analyze
     * @return true if VulnDbAnalysisTask should analyze, false if not
     */
    public boolean isCapable(final Component component) {
        return component.getCpe() != null;
    }

    /**
     * Analyzes a list of Components.
     * @param components a list of Components
     */
    public void analyze(final List<Component> components) {
        final VulnDbApi api = new VulnDbApi(this.apiConsumerKey, this.apiConsumerSecret, UnirestFactory.getUnirestInstance());
        for (final Component component: components) {
            if (!component.isInternal() && isCapable(component)
                    && !isCacheCurrent(Vulnerability.Source.VULNDB, TARGET_HOST, component.getCpe())) {
                int page = 1;
                boolean more = true;
                while (more) {
                    final Results results = api.getVulnerabilitiesByCpe(component.getCpe(), PAGE_SIZE, page);
                    if (results.isSuccessful()) {
                        more = processResults(results, component);
                        page++;
                    } else {
                        LOGGER.error(results.getErrorCondition());
                        return;
                    }
                }
            }
        }
    }

    @SuppressWarnings("unchecked")
    private boolean processResults(final Results results, final Component component) {
        try (final QueryManager qm = new QueryManager()) {
            final Component vulnerableComponent = qm.getObjectByUuid(Component.class, component.getUuid()); // Refresh component and attach to current pm.
            for (us.springett.vulndbdatamirror.parser.model.Vulnerability vulnDbVuln : (List<us.springett.vulndbdatamirror.parser.model.Vulnerability>) results.getResults()) {
                Vulnerability vulnerability = qm.getVulnerabilityByVulnId(Vulnerability.Source.VULNDB, String.valueOf(vulnDbVuln.getId()));
                if (vulnerability == null) {
                    vulnerability = qm.createVulnerability(ModelConverter.convert(qm, vulnDbVuln), false);
                } else {
                    vulnerability = qm.synchronizeVulnerability(ModelConverter.convert(qm, vulnDbVuln), false);
                }
                NotificationUtil.analyzeNotificationCriteria(qm, vulnerability, vulnerableComponent);
                qm.addVulnerability(vulnerability, vulnerableComponent, this.getAnalyzerIdentity());
                addVulnerabilityToCache(vulnerableComponent, vulnerability);
            }
            updateAnalysisCacheStats(qm, Vulnerability.Source.VULNDB, TARGET_HOST, vulnerableComponent.getCpe(), component.getCacheResult());
            return results.getPage() * PAGE_SIZE < results.getTotal();
        }
    }
}
