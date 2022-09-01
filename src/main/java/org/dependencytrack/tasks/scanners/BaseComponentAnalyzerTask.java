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
import alpine.common.util.BooleanUtil;
import alpine.model.ConfigProperty;
import alpine.notification.Notification;
import alpine.notification.NotificationLevel;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.ComponentAnalysisCache;
import org.dependencytrack.model.ConfigPropertyConstants;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.notification.NotificationConstants;
import org.dependencytrack.notification.NotificationGroup;
import org.dependencytrack.notification.NotificationScope;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.util.NotificationUtil;

import javax.json.Json;
import javax.json.JsonArray;
import javax.json.JsonArrayBuilder;
import javax.json.JsonNumber;
import javax.json.JsonObject;
import java.util.Date;

/**
 * A base class that has logic common or useful to all classes that extend it.
 *
 * @author Steve Springett
 * @since 3.0.0
 */
public abstract class BaseComponentAnalyzerTask implements ScanTask {

    private final Logger LOGGER = Logger.getLogger(this.getClass()); // We dont want this class reporting the logger

    protected boolean isEnabled(final ConfigPropertyConstants configPropertyConstants) {
        try (QueryManager qm = new QueryManager()) {
            final ConfigProperty property = qm.getConfigProperty(
                    configPropertyConstants.getGroupName(), configPropertyConstants.getPropertyName()
            );
            if (property != null && ConfigProperty.PropertyType.BOOLEAN == property.getPropertyType()) {
                return BooleanUtil.valueOf(property.getPropertyValue());
            }
            return false;
        }
    }

    protected boolean isCacheCurrent(Vulnerability.Source source, String targetHost, String target) {
        try (QueryManager qm = new QueryManager()) {
            boolean isCacheCurrent = false;
            ConfigProperty cacheClearPeriod = qm.getConfigProperty(ConfigPropertyConstants.SCANNER_ANALYSIS_CACHE_VALIDITY_PERIOD.getGroupName(), ConfigPropertyConstants.SCANNER_ANALYSIS_CACHE_VALIDITY_PERIOD.getPropertyName());
            long cacheValidityPeriod = Long.valueOf(cacheClearPeriod.getPropertyValue());
            ComponentAnalysisCache cac = qm.getComponentAnalysisCache(ComponentAnalysisCache.CacheType.VULNERABILITY, targetHost, source.name(), target);
            if (cac != null) {
                final Date now = new Date();
                if (now.getTime() > cac.getLastOccurrence().getTime()) {
                    final long delta = now.getTime() - cac.getLastOccurrence().getTime();
                    isCacheCurrent = delta <= cacheValidityPeriod;
                }
            }
            if (isCacheCurrent) {
                LOGGER.debug("Cache is current. Skipping analysis. (source: " + source + " / targetHost: " + targetHost + " / target: " + target);
            } else {
                LOGGER.debug("Cache is not current. Analysis should be performed (source: " + source + " / targetHost: " + targetHost + " / target: " + target);
            }
            return isCacheCurrent;
        }
    }

    protected void applyAnalysisFromCache(Vulnerability.Source source, String targetHost, String target, Component component, AnalyzerIdentity analyzerIdentity) {
        try (QueryManager qm = new QueryManager()) {
            final ComponentAnalysisCache cac = qm.getComponentAnalysisCache(ComponentAnalysisCache.CacheType.VULNERABILITY, targetHost, source.name(), target);
            if (cac != null) {
                final JsonObject result = cac.getResult();
                if (result != null) {
                    final JsonArray vulns = result.getJsonArray("vulnIds");
                    if (vulns != null) {
                        for (JsonNumber vulnId : vulns.getValuesAs(JsonNumber.class)) {
                            final Vulnerability vulnerability = qm.getObjectById(Vulnerability.class, vulnId.longValue());
                            final Component c = qm.getObjectByUuid(Component.class, component.getUuid());
                            if (c == null) continue;
                            if (vulnerability != null) {
                                NotificationUtil.analyzeNotificationCriteria(qm, vulnerability, component);
                                qm.addVulnerability(vulnerability, c, analyzerIdentity);
                            }
                        }
                    }
                }
            }
        }
    }

    protected synchronized void updateAnalysisCacheStats(QueryManager qm, Vulnerability.Source source, String targetHost, String target, JsonObject result) {
        qm.updateComponentAnalysisCache(ComponentAnalysisCache.CacheType.VULNERABILITY, targetHost, source.name(), target, new Date(), result);
    }

    protected void addVulnerabilityToCache(Component component, Vulnerability vulnerability) {
        if (component.getCacheResult() == null) {
            final JsonArray vulns = Json.createArrayBuilder().add(vulnerability.getId()).build();
            final JsonObject result = Json.createObjectBuilder().add("vulnIds", vulns).build();
            component.setCacheResult(result);
        } else {
            final JsonObject result = component.getCacheResult();
            final JsonArrayBuilder vulnsBuilder = Json.createArrayBuilder(result.getJsonArray("vulnIds"));
            final JsonArray vulns = vulnsBuilder.add(Json.createValue(vulnerability.getId())).build();
            component.setCacheResult(Json.createObjectBuilder(result).add("vulnIds", vulns).build());
        }
    }

    protected void handleUnexpectedHttpResponse(final Logger logger, String url, final int statusCode, final String statusText) {
        logger.error("HTTP Status : " + statusCode + " " + statusText);
        logger.error(" - Analyzer URL : " + url);
        Notification.dispatch(new Notification()
                .scope(NotificationScope.SYSTEM)
                .group(NotificationGroup.ANALYZER)
                .title(NotificationConstants.Title.ANALYZER_ERROR)
                .content("An error occurred while communicating with a vulnerability intelligence source. URL: " + url + " HTTP Status: " + statusCode + ". Check log for details." )
                .level(NotificationLevel.ERROR)
        );
    }

    protected void handleRequestException(final Logger logger, final Exception e) {
        logger.error("Request failure", e);
        Notification.dispatch(new Notification()
                .scope(NotificationScope.SYSTEM)
                .group(NotificationGroup.ANALYZER)
                .title(NotificationConstants.Title.ANALYZER_ERROR)
                .content("An error occurred while communicating with a vulnerability intelligence source. Check log for details. " + e.getMessage())
                .level(NotificationLevel.ERROR)
        );
    }
}
