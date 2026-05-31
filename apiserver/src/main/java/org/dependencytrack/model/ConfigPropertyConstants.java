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
package org.dependencytrack.model;

import alpine.model.IConfigProperty;
import alpine.model.IConfigProperty.PropertyType;
import org.dependencytrack.common.ConfigKeys;
import org.eclipse.microprofile.config.ConfigProvider;

import java.util.Arrays;
import java.util.UUID;

public enum ConfigPropertyConstants {

    INTERNAL_CLUSTER_ID("internal", "cluster.id", UUID.randomUUID().toString(), PropertyType.STRING, "Unique identifier of the cluster", ConfigPropertyAccessMode.READ_ONLY),
    INTERNAL_DEFAULT_OBJECTS_VERSION("internal", "default.objects.version", null, PropertyType.STRING, "Version of the default objects in the database", ConfigPropertyAccessMode.READ_ONLY),
    GENERAL_BASE_URL("general", "base.url", null, PropertyType.URL, "URL used to construct links back to Dependency-Track from external systems", ConfigPropertyAccessMode.READ_WRITE),
    GENERAL_BADGE_ENABLED("general", "badge.enabled", "false", PropertyType.BOOLEAN, "Flag to enable/disable public access to SVG badges", ConfigPropertyAccessMode.READ_WRITE),
    INTERNAL_COMPONENTS_GROUPS_REGEX("internal-components", "groups.regex", null, PropertyType.STRING, "Regex that matches groups of internal components", ConfigPropertyAccessMode.READ_WRITE),
    INTERNAL_COMPONENTS_NAMES_REGEX("internal-components", "names.regex", null, PropertyType.STRING, "Regex that matches names of internal components", ConfigPropertyAccessMode.READ_WRITE),
    INTERNAL_COMPONENTS_MATCH_MODE("internal-components", "match-mode", "OR", PropertyType.STRING, "Determines how internal component regexes are combined: OR (default) or AND", ConfigPropertyAccessMode.READ_WRITE),
    MAINTENANCE_METRICS_RETENTION_DAYS("maintenance", "metrics.retention.days", "90", PropertyType.INTEGER, "Number of days to retain metrics data for", ConfigPropertyAccessMode.READ_WRITE),
    MAINTENANCE_PROJECTS_RETENTION_DAYS("maintenance", "projects.retention.days", "30", PropertyType.INTEGER, "Number of days to retain inactive projects for", ConfigPropertyAccessMode.READ_WRITE),
    MAINTENANCE_PROJECTS_RETENTION_TYPE("maintenance", "projects.retention.type", null, PropertyType.STRING, "Retention policy type for inactive projects", ConfigPropertyAccessMode.READ_WRITE),
    MAINTENANCE_PROJECTS_RETENTION_VERSIONS("maintenance", "projects.retention.versions", "2", PropertyType.INTEGER, "Number of last inactive projects to retain and delete rest", ConfigPropertyAccessMode.READ_WRITE),
    MAINTENANCE_TAGS_DELETE_UNUSED("maintenance", "tags.delete.unused", "true", PropertyType.BOOLEAN, "Whether unused tags shall be deleted", ConfigPropertyAccessMode.READ_WRITE),
    MAINTENANCE_VULNERABILITY_SCAN_RETENTION_HOURS("maintenance", "vuln.scan.retention.hours", "24", PropertyType.INTEGER, "Number of hours to retain vulnerability scan records for", ConfigPropertyAccessMode.READ_WRITE),
    VULNERABILITY_POLICY_FILE_LAST_MODIFIED_HASH("vulnerability-policy", "vulnerability.policy.file.last.modified.hash", null, PropertyType.STRING, "Hash value or etag of the last fetched bundle if any", ConfigPropertyAccessMode.READ_ONLY),
    VULNERABILITY_SOURCE_EPSS_ENABLED("vuln-source", "epss.enabled", "true", PropertyType.BOOLEAN, "Flag to enable/disable Exploit Prediction Scoring System", ConfigPropertyAccessMode.READ_WRITE),
    VULNERABILITY_SOURCE_EPSS_FEEDS_URL("vuln-source", "epss.feeds.url", "https://epss.empiricalsecurity.com", PropertyType.URL, "A base URL pointing to the hostname and path of the EPSS feeds", ConfigPropertyAccessMode.READ_WRITE),
    ACCEPT_ARTIFACT_CYCLONEDX("artifact", "cyclonedx.enabled", "true", PropertyType.BOOLEAN, "Flag to enable/disable the systems ability to accept CycloneDX uploads", ConfigPropertyAccessMode.READ_WRITE),
    BOM_VALIDATION_MODE("artifact", "bom.validation.mode", BomValidationMode.ENABLED.name(), PropertyType.STRING, "Flag to control the BOM validation mode", ConfigPropertyAccessMode.READ_WRITE),
    BOM_VALIDATION_TAGS_INCLUSIVE("artifact", "bom.validation.tags.inclusive", "[]", PropertyType.STRING, "JSON array of tags for which BOM validation shall be performed", ConfigPropertyAccessMode.READ_WRITE),
    BOM_VALIDATION_TAGS_EXCLUSIVE("artifact", "bom.validation.tags.exclusive", "[]", PropertyType.STRING, "JSON array of tags for which BOM validation shall NOT be performed", ConfigPropertyAccessMode.READ_WRITE),
    FORTIFY_SSC_ENABLED("integrations", "fortify.ssc.enabled", "false", PropertyType.BOOLEAN, "Flag to enable/disable Fortify SSC integration", ConfigPropertyAccessMode.READ_WRITE),
    FORTIFY_SSC_URL("integrations", "fortify.ssc.url", null, PropertyType.URL, "Base URL to Fortify SSC", ConfigPropertyAccessMode.READ_WRITE),
    FORTIFY_SSC_TOKEN("integrations", "fortify.ssc.token", null, PropertyType.STRING, "Name of the secret containing the Fortify SSC authentication token", ConfigPropertyAccessMode.READ_WRITE, false, true),
    DEFECTDOJO_ENABLED("integrations", "defectdojo.enabled", "false", PropertyType.BOOLEAN, "Flag to enable/disable DefectDojo integration", ConfigPropertyAccessMode.READ_WRITE),
    DEFECTDOJO_REIMPORT_ENABLED("integrations", "defectdojo.reimport.enabled", "false", PropertyType.BOOLEAN, "Flag to enable/disable DefectDojo reimport-scan API endpoint", ConfigPropertyAccessMode.READ_WRITE),
    DEFECTDOJO_URL("integrations", "defectdojo.url", null, PropertyType.URL, "Base URL to DefectDojo", ConfigPropertyAccessMode.READ_WRITE),
    DEFECTDOJO_API_KEY("integrations", "defectdojo.apiKey", null, PropertyType.STRING, "Name of the secret containing the DefectDojo API key", ConfigPropertyAccessMode.READ_WRITE, false, true),
    KENNA_ENABLED("integrations", "kenna.enabled", "false", PropertyType.BOOLEAN, "Flag to enable/disable Kenna Security integration", ConfigPropertyAccessMode.READ_WRITE),
    KENNA_API_URL("integrations", "kenna.api.url", "https://api.kennasecurity.com", PropertyType.STRING, "Kenna Security API URL", ConfigPropertyAccessMode.READ_WRITE),
    KENNA_TOKEN("integrations", "kenna.token", null, PropertyType.STRING, "Name of the secret containing the Kenna Security authentication token", ConfigPropertyAccessMode.READ_WRITE, false, true),
    KENNA_CONNECTOR_ID("integrations", "kenna.connector.id", null, PropertyType.STRING, "The Kenna Security connector identifier to upload to", ConfigPropertyAccessMode.READ_WRITE),
    ACCESS_MANAGEMENT_ACL_ENABLED("access-management", "acl.enabled", "false", PropertyType.BOOLEAN, "Flag to enable/disable access control to projects in the portfolio", ConfigPropertyAccessMode.READ_WRITE, true),
    CUSTOM_RISK_SCORE_HISTORY_ENABLED("risk-score", "weight.history.enabled", "true", PropertyType.BOOLEAN, "Flag to re-calculate risk score history", ConfigPropertyAccessMode.READ_WRITE),
    CUSTOM_RISK_SCORE_CRITICAL("risk-score", "weight.critical", "10", PropertyType.INTEGER, "Critical severity vulnerability weight (between 1-10)", ConfigPropertyAccessMode.READ_WRITE),
    CUSTOM_RISK_SCORE_HIGH("risk-score", "weight.high", "5", PropertyType.INTEGER, "High severity vulnerability weight (between 1-10)", ConfigPropertyAccessMode.READ_WRITE),
    CUSTOM_RISK_SCORE_MEDIUM("risk-score", "weight.medium", "3", PropertyType.INTEGER, "Medium severity vulnerability weight (between 1-10)", ConfigPropertyAccessMode.READ_WRITE),
    CUSTOM_RISK_SCORE_LOW("risk-score", "weight.low", "1", PropertyType.INTEGER, "Low severity vulnerability weight (between 1-10)", ConfigPropertyAccessMode.READ_WRITE),
    CUSTOM_RISK_SCORE_UNASSIGNED("risk-score", "weight.unassigned", "5", PropertyType.INTEGER, "Unassigned severity vulnerability weight (between 1-10)", ConfigPropertyAccessMode.READ_WRITE),
    WELCOME_MESSAGE("general", "welcome.message.html", "%3Chtml%3E%3Ch1%3EYour%20Welcome%20Message%3C%2Fh1%3E%3C%2Fhtml%3E", PropertyType.STRING, "Custom HTML Code that is displayed before login", ConfigPropertyAccessMode.READ_WRITE, true),
    IS_WELCOME_MESSAGE("general", "welcome.message.enabled", "false", PropertyType.BOOLEAN, "Bool that says whether to show the welcome message or not", ConfigPropertyAccessMode.READ_WRITE, true),
    DEFAULT_LANGUAGE("general", "default.locale", null, PropertyType.STRING, "Determine the default Language to use", ConfigPropertyAccessMode.READ_WRITE, true),
    TELEMETRY_SUBMISSION_ENABLED("telemetry", "submission.enabled", ConfigProvider.getConfig().getOptionalValue(ConfigKeys.TELEMETRY_SUBMISSION_DEFAULT_ENABLED, boolean.class).map(String::valueOf).orElse("true"), PropertyType.BOOLEAN, "Whether submission of telemetry data is enabled", ConfigPropertyAccessMode.READ_WRITE),
    TELEMETRY_LAST_SUBMISSION_DATA("telemetry", "last.submission.data", null, PropertyType.STRING, "Data of the last telemetry submission", ConfigPropertyAccessMode.READ_ONLY),
    TELEMETRY_LAST_SUBMISSION_EPOCH_SECONDS("telemetry", "last.submission.epoch.seconds", null, PropertyType.INTEGER, "Timestamp of the last telemetry submission in epoch seconds", ConfigPropertyAccessMode.READ_ONLY);

    private final String groupName;
    private final String propertyName;
    private final String defaultPropertyValue;
    private final PropertyType propertyType;
    private final String description;
    private final ConfigPropertyAccessMode accessMode;
    private final Boolean isPublic;
    private final boolean isSecretName;

    ConfigPropertyConstants(
            String groupName,
            String propertyName,
            String defaultPropertyValue,
            PropertyType propertyType,
            String description,
            ConfigPropertyAccessMode accessMode) {
        this(groupName, propertyName, defaultPropertyValue, propertyType, description, accessMode, false, false);
    }

    ConfigPropertyConstants(
            String groupName,
            String propertyName,
            String defaultPropertyValue,
            PropertyType propertyType,
            String description,
            ConfigPropertyAccessMode accessMode,
            Boolean isPublic) {
        this(groupName, propertyName, defaultPropertyValue, propertyType, description, accessMode, isPublic, false);
    }

    ConfigPropertyConstants(
            String groupName,
            String propertyName,
            String defaultPropertyValue,
            PropertyType propertyType,
            String description,
            ConfigPropertyAccessMode accessMode,
            Boolean isPublic,
            boolean isSecretName) {
        this.groupName = groupName;
        this.propertyName = propertyName;
        this.defaultPropertyValue = defaultPropertyValue;
        this.propertyType = propertyType;
        this.description = description;
        this.accessMode = accessMode;
        this.isPublic = isPublic;
        this.isSecretName = isSecretName;
    }

    public static ConfigPropertyConstants ofProperty(final IConfigProperty property) {
        return Arrays.stream(values())
                .filter(value -> value.groupName.equals(property.getGroupName())
                        && value.propertyName.equals(property.getPropertyName()))
                .findFirst()
                .orElse(null);
    }

    public String getGroupName() {
        return groupName;
    }

    public String getPropertyName() {
        return propertyName;
    }

    public String getDefaultPropertyValue() {
        return defaultPropertyValue;
    }

    public PropertyType getPropertyType() {
        return propertyType;
    }

    public String getDescription() {
        return description;
    }

    public ConfigPropertyAccessMode getAccessMode() {
        return accessMode;
    }

    public Boolean getIsPublic() {
        return isPublic;
    }

    public boolean isSecretName() {
        return isSecretName;
    }

}
