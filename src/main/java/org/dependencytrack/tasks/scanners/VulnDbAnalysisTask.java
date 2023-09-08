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
import oauth.signpost.exception.OAuthCommunicationException;
import oauth.signpost.exception.OAuthExpectationFailedException;
import oauth.signpost.exception.OAuthMessageSignerException;
import org.dependencytrack.event.VulnDbAnalysisEvent;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.ConfigPropertyConstants;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.VulnerabilityAnalysisLevel;
import org.dependencytrack.parser.vulndb.ModelConverter;
import org.dependencytrack.parser.vulndb.VulnDbClient;
import org.dependencytrack.parser.vulndb.model.Results;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.util.NotificationUtil;
import java.io.IOException;
import java.net.URISyntaxException;
import java.util.List;

/**
 * Subscriber task that performs an analysis of component using VulnDB REST API.
 *
 * @author Steve Springett
 * @since 3.6.0
 */
public class VulnDbAnalysisTask extends BaseComponentAnalyzerTask implements Subscriber {


    private static final Logger LOGGER = Logger.getLogger(VulnDbAnalysisTask.class);
    private static final int PAGE_SIZE = 100;
    private VulnerabilityAnalysisLevel vulnerabilityAnalysisLevel;
    private String apiConsumerKey;
    private String apiConsumerSecret;

    private String apiBaseUrl;

    @Override
    public AnalyzerIdentity getAnalyzerIdentity() {
        return AnalyzerIdentity.VULNDB_ANALYZER;
    }

    public VulnDbAnalysisTask(String apiBaseUrl) {
        this.apiBaseUrl = apiBaseUrl;
    }

    public VulnDbAnalysisTask() {
        this("https://vulndb.cyberriskanalytics.com");
    }

    /**
     * {@inheritDoc}
     */
    @Override
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
                if (this.apiBaseUrl == null) {
                    LOGGER.warn("No API base URL provided; Skipping");
                    return;
                }

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
            final var event = (VulnDbAnalysisEvent) e;
            vulnerabilityAnalysisLevel = event.getVulnerabilityAnalysisLevel();
            LOGGER.debug("Starting VulnDB analysis task");
            if (!event.getComponents().isEmpty()) {
                analyze(event.getComponents());
            }
            LOGGER.debug("VulnDB analysis complete");
        }
    }

    /**
     * Determines if the {@link VulnDbAnalysisTask} is capable of analyzing the specified Component.
     *
     * @param component the Component to analyze
     * @return true if VulnDbAnalysisTask should analyze, false if not
     */
    @Override
    public boolean isCapable(final Component component) {
        return component.getCpe() != null;
    }

    /**
     * Analyzes a list of Components.
     *
     * @param components a list of Components
     */
    @Override
    public void analyze(final List<Component> components) {
        final var api = new VulnDbClient(this.apiConsumerKey, this.apiConsumerSecret, this.apiBaseUrl);
        for (final Component component : components) {
            if (isCacheCurrent(Vulnerability.Source.VULNDB, apiBaseUrl, component.getCpe())) {
                applyAnalysisFromCache(Vulnerability.Source.VULNDB, apiBaseUrl, component.getCpe(), component, AnalyzerIdentity.VULNDB_ANALYZER, vulnerabilityAnalysisLevel);
            } else if (!component.isInternal() && isCapable(component)
                    && !isCacheCurrent(Vulnerability.Source.VULNDB, apiBaseUrl, component.getCpe())) {
                if (!component.isInternal() && isCapable(component)
                        && !isCacheCurrent(Vulnerability.Source.VULNDB, apiBaseUrl, component.getCpe())) {
                    int page = 1;
                    boolean more = true;
                    while (more) {
                        try {
                            final Results results = api.getVulnerabilitiesByCpe(component.getCpe(), PAGE_SIZE, page);
                            if (results.isSuccessful()) {
                                more = processResults(results, component);
                                page++;
                            } else {
                                LOGGER.warn(results.getErrorCondition());
                                handleRequestException(LOGGER, new Exception(results.getErrorCondition()));
                                return;
                            }
                        } catch (IOException | OAuthMessageSignerException | OAuthExpectationFailedException |
                                 URISyntaxException | OAuthCommunicationException ex) {
                            handleRequestException(LOGGER, ex);
                        }
                    }
                }
            }
        }
    }

    @SuppressWarnings("unchecked")
    private boolean processResults(final Results results, final Component component) {
        try (final QueryManager qm = new QueryManager()) {
            final Component vulnerableComponent = qm.getObjectByUuid(Component.class, component.getUuid()); // Refresh component and attach to current pm.
            for (org.dependencytrack.parser.vulndb.model.Vulnerability vulnDbVuln : (List<org.dependencytrack.parser.vulndb.model.Vulnerability>) results.getResults()) {
                Vulnerability vulnerability = qm.getVulnerabilityByVulnId(Vulnerability.Source.VULNDB, String.valueOf(vulnDbVuln.id()));
                if (vulnerability == null) {
                    vulnerability = qm.createVulnerability(ModelConverter.convert(qm, vulnDbVuln), false);
                } else {
                    vulnerability = qm.synchronizeVulnerability(ModelConverter.convert(qm, vulnDbVuln), false);
                }
                NotificationUtil.analyzeNotificationCriteria(qm, vulnerability, vulnerableComponent, vulnerabilityAnalysisLevel);
                qm.addVulnerability(vulnerability, vulnerableComponent, this.getAnalyzerIdentity());
                addVulnerabilityToCache(vulnerableComponent, vulnerability);
            }
            updateAnalysisCacheStats(qm, Vulnerability.Source.VULNDB, apiBaseUrl, vulnerableComponent.getCpe(), vulnerableComponent.getCacheResult());
            return results.getPage() * PAGE_SIZE < results.getTotal();
        }
    }

}
