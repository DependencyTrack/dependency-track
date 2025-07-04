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

import alpine.Config;
import alpine.model.IConfigProperty;
import alpine.model.IConfigProperty.PropertyType;
import org.apache.commons.lang3.SystemUtils;
import org.dependencytrack.common.ConfigKey;

import java.util.Arrays;

public enum ConfigPropertyConstants {

    GENERAL_BASE_URL("general", "base.url", null, PropertyType.URL, "URL used to construct links back to Dependency-Track from external systems"),
    GENERAL_BADGE_ENABLED("general", "badge.enabled", "false", PropertyType.BOOLEAN, "Flag to enable/disable unauthenticated access to SVG badge from metrics"),
    EMAIL_SMTP_ENABLED("email", "smtp.enabled", "false", PropertyType.BOOLEAN, "Flag to enable/disable SMTP"),
    EMAIL_SMTP_FROM_ADDR("email", "smtp.from.address", null, PropertyType.STRING, "The from email address to use to send output SMTP mail"),
    EMAIL_PREFIX("email", "subject.prefix", "[Dependency-Track]", PropertyType.STRING, "The Prefix Subject email to use"),
    EMAIL_SMTP_SERVER_HOSTNAME("email", "smtp.server.hostname", null, PropertyType.STRING, "The hostname or IP address of the SMTP mail server"),
    EMAIL_SMTP_SERVER_PORT("email", "smtp.server.port", null, PropertyType.INTEGER, "The port the SMTP server listens on"),
    EMAIL_SMTP_USERNAME("email", "smtp.username", null, PropertyType.STRING, "The optional username to authenticate with when sending outbound SMTP mail"),
    EMAIL_SMTP_PASSWORD("email", "smtp.password", null, PropertyType.ENCRYPTEDSTRING, "The optional password for the username used for authentication"),
    EMAIL_SMTP_SSLTLS("email", "smtp.ssltls", "false", PropertyType.BOOLEAN, "Flag to enable/disable the use of SSL/TLS when connecting to the SMTP server"),
    EMAIL_SMTP_TRUSTCERT("email", "smtp.trustcert", "false", PropertyType.BOOLEAN, "Flag to enable/disable the trust of the certificate presented by the SMTP server"),
    INTERNAL_COMPONENTS_GROUPS_REGEX("internal-components", "groups.regex", null, PropertyType.STRING, "Regex that matches groups of internal components"),
    INTERNAL_COMPONENTS_NAMES_REGEX("internal-components", "names.regex", null, PropertyType.STRING, "Regex that matches names of internal components"),
    INTERNAL_COMPONENTS_MATCH_MODE("internal-components", "match-mode", "OR", PropertyType.STRING, "Determines how internal component regexes are combined: OR (default) or AND"),
    JIRA_URL("integrations", "jira.url", null, PropertyType.URL, "The base URL of the JIRA instance"),
    JIRA_USERNAME("integrations", "jira.username", null, PropertyType.STRING, "The optional username to authenticate with when creating an Jira issue"),
    JIRA_PASSWORD("integrations", "jira.password", null, PropertyType.ENCRYPTEDSTRING, "The password for the username or bearer token used for authentication"),
    SCANNER_INTERNAL_ENABLED("scanner", "internal.enabled", "true", PropertyType.BOOLEAN, "Flag to enable/disable the internal analyzer"),
    SCANNER_INTERNAL_FUZZY_ENABLED("scanner", "internal.fuzzy.enabled", "false", PropertyType.BOOLEAN, "Flag to enable/disable non-exact fuzzy matching using the internal analyzer"),
    SCANNER_INTERNAL_FUZZY_EXCLUDE_PURL("scanner", "internal.fuzzy.exclude.purl", "true", PropertyType.BOOLEAN, "Flag to enable/disable fuzzy matching on components that have a Package URL (PURL) defined"),
    SCANNER_INTERNAL_FUZZY_EXCLUDE_INTERNAL("scanner", "internal.fuzzy.exclude.internal", "true", PropertyType.BOOLEAN, "Flag to enable/disable fuzzy matching on components that are marked internal."),
    SCANNER_NPMAUDIT_ENABLED("scanner", "npmaudit.enabled", "true", PropertyType.BOOLEAN, "Flag to enable/disable NPM Audit"),
    SCANNER_OSSINDEX_ENABLED("scanner", "ossindex.enabled", "true", PropertyType.BOOLEAN, "Flag to enable/disable Sonatype OSS Index"),
    SCANNER_OSSINDEX_ALIAS_SYNC_ENABLED("scanner", "ossindex.alias.sync.enabled", "true", PropertyType.BOOLEAN, "Flag to enable/disable alias synchronization for OSS Index"),
    SCANNER_OSSINDEX_API_USERNAME("scanner", "ossindex.api.username", null, PropertyType.STRING, "The API username used for OSS Index authentication"),
    SCANNER_OSSINDEX_API_TOKEN("scanner", "ossindex.api.token", null, PropertyType.ENCRYPTEDSTRING, "The API token used for OSS Index authentication"),
    SCANNER_VULNDB_ENABLED("scanner", "vulndb.enabled", "false", PropertyType.BOOLEAN, "Flag to enable/disable VulnDB"),
    SCANNER_VULNDB_OAUTH1_CONSUMER_KEY("scanner", "vulndb.api.oauth1.consumerKey", null, PropertyType.STRING, "The OAuth 1.0a consumer key"),
    SCANNER_VULNDB_OAUTH1_CONSUMER_SECRET("scanner", "vulndb.api.oath1.consumerSecret", null, PropertyType.ENCRYPTEDSTRING, "The OAuth 1.0a consumer secret"),
    SCANNER_ANALYSIS_CACHE_VALIDITY_PERIOD("scanner", "analysis.cache.validity.period","43200000", PropertyType.NUMBER, "Validity period for individual component vulnerability and metadats analysis cache"),
    SCANNER_SNYK_ENABLED("scanner", "snyk.enabled", "false", PropertyType.BOOLEAN, "Flag to enable/disable Snyk Vulnerability Analysis"),
    SCANNER_SNYK_ALIAS_SYNC_ENABLED("scanner", "snyk.alias.sync.enabled", "false", PropertyType.BOOLEAN, "Flag to enable/disable alias synchronization for Snyk"),
    SCANNER_SNYK_API_TOKEN("scanner", "snyk.api.token", null, PropertyType.ENCRYPTEDSTRING, "The API token used for Snyk API authentication"),
    SCANNER_SNYK_ORG_ID("scanner", "snyk.org.id", null, PropertyType.STRING, "The Organization ID used for Snyk API access"),
    SCANNER_SNYK_API_VERSION("scanner", "snyk.api.version", "2023-06-22", PropertyType.STRING, "Snyk API version"),
    SCANNER_SNYK_CVSS_SOURCE("scanner", "snyk.cvss.source", "NVD", PropertyType.STRING, "Type of source to be prioritized for cvss calculation"),
    SCANNER_SNYK_BASE_URL("scanner", "snyk.base.url", "https://api.snyk.io", PropertyType.URL, "Base Url pointing to the hostname and path for Snyk analysis"),
    SCANNER_TRIVY_ENABLED("scanner", "trivy.enabled", "false", PropertyType.BOOLEAN, "Flag to enable/disable Trivy Vulnerability Analysis"),
    SCANNER_TRIVY_API_TOKEN("scanner", "trivy.api.token", null, PropertyType.ENCRYPTEDSTRING, "The API token used for Trivy API authentication"),
    SCANNER_TRIVY_BASE_URL("scanner", "trivy.base.url", null, PropertyType.URL, "Base Url pointing to the hostname and path for Trivy analysis"),
    SCANNER_TRIVY_IGNORE_UNFIXED("scanner", "trivy.ignore.unfixed", "false", PropertyType.BOOLEAN, "Flag to ignore unfixed vulnerabilities"),
    SCANNER_TRIVY_SCAN_LIBRARY("scanner", "trivy.scanner.scanLibrary", "true", PropertyType.BOOLEAN, "Flag to enable library scanning"),
    SCANNER_TRIVY_SCAN_OS("scanner", "trivy.scanner.scanOs", "true", PropertyType.BOOLEAN, "Flag to enable os scanning"),
    VULNERABILITY_SOURCE_NVD_ENABLED("vuln-source", "nvd.enabled", "true", PropertyType.BOOLEAN, "Flag to enable/disable National Vulnerability Database"),
    VULNERABILITY_SOURCE_NVD_FEEDS_URL("vuln-source", "nvd.feeds.url", "https://nvd.nist.gov/feeds", PropertyType.URL, "A base URL pointing to the hostname and path of the NVD feeds"),
    VULNERABILITY_SOURCE_NVD_API_ENABLED("vuln-source", "nvd.api.enabled", "false", PropertyType.BOOLEAN, "Whether to enable NVD mirroring via REST API"),
    VULNERABILITY_SOURCE_NVD_API_DOWNLOAD_FEEDS("vuln-source", "nvd.api.download.feeds", "false", PropertyType.BOOLEAN, "Whether to download feed files even though mirroring via REST API is enabled"),
    VULNERABILITY_SOURCE_NVD_API_URL("vuln-source", "nvd.api.url", "https://services.nvd.nist.gov/rest/json/cves/2.0", PropertyType.URL, "REST API URL for the NVD's CVE API 2.0"),
    VULNERABILITY_SOURCE_NVD_API_KEY("vuln-source", "nvd.api.key", null, PropertyType.ENCRYPTEDSTRING, "API key for the NVD REST API"),
    VULNERABILITY_SOURCE_NVD_API_LAST_MODIFIED_EPOCH_SECONDS("vuln-source", "nvd.api.last.modified.epoch.seconds", null, PropertyType.INTEGER, "Epoch timestamp in seconds of the latest observed CVE modification time"),
    VULNERABILITY_SOURCE_GITHUB_ADVISORIES_ENABLED("vuln-source", "github.advisories.enabled", "false", PropertyType.BOOLEAN, "Flag to enable/disable GitHub Advisories"),
    VULNERABILITY_SOURCE_GITHUB_ADVISORIES_API_URL("vuln-source", "github.advisories.api.url", "https://api.github.com/graphql", PropertyType.STRING, "URL of the GitHub GraphQL API"),
    VULNERABILITY_SOURCE_GITHUB_ADVISORIES_ALIAS_SYNC_ENABLED("vuln-source", "github.advisories.alias.sync.enabled", "true", PropertyType.BOOLEAN, "Flag to enable/disable alias synchronization for GitHub Advisories"),
    VULNERABILITY_SOURCE_GITHUB_ADVISORIES_ACCESS_TOKEN("vuln-source", "github.advisories.access.token", null, PropertyType.STRING, "The access token used for GitHub API authentication"),
    VULNERABILITY_SOURCE_GITHUB_ADVISORIES_LAST_MODIFIED_EPOCH_SECONDS("vuln-source", "github.advisories.last.modified.epoch.seconds", null, PropertyType.INTEGER, "Epoch timestamp in seconds of the latest observed GHSA modification time"),
    VULNERABILITY_SOURCE_GOOGLE_OSV_BASE_URL("vuln-source", "google.osv.base.url", "https://osv-vulnerabilities.storage.googleapis.com/", PropertyType.URL, "A base URL pointing to the hostname and path for OSV mirroring"),
    VULNERABILITY_SOURCE_GOOGLE_OSV_ENABLED("vuln-source", "google.osv.enabled", null, PropertyType.STRING, "List of enabled ecosystems to mirror OSV"),
    VULNERABILITY_SOURCE_GOOGLE_OSV_ALIAS_SYNC_ENABLED("vuln-source", "google.osv.alias.sync.enabled", "false", PropertyType.BOOLEAN, "Flag to enable/disable alias synchronization for OSV"),
    VULNERABILITY_SOURCE_EPSS_ENABLED("vuln-source", "epss.enabled", "true", PropertyType.BOOLEAN, "Flag to enable/disable Exploit Prediction Scoring System"),
    VULNERABILITY_SOURCE_EPSS_FEEDS_URL("vuln-source", "epss.feeds.url", "https://epss.cyentia.com", PropertyType.URL, "A base URL pointing to the hostname and path of the EPSS feeds"),
    ACCEPT_ARTIFACT_CYCLONEDX("artifact", "cyclonedx.enabled", "true", PropertyType.BOOLEAN, "Flag to enable/disable the systems ability to accept CycloneDX uploads"),
    FORTIFY_SSC_ENABLED("integrations", "fortify.ssc.enabled", "false", PropertyType.BOOLEAN, "Flag to enable/disable Fortify SSC integration"),
    FORTIFY_SSC_SYNC_CADENCE("integrations", "fortify.ssc.sync.cadence", "60", PropertyType.INTEGER, "The cadence (in minutes) to upload to Fortify SSC"),
    FORTIFY_SSC_URL("integrations", "fortify.ssc.url", null, PropertyType.URL, "Base URL to Fortify SSC"),
    FORTIFY_SSC_TOKEN("integrations", "fortify.ssc.token", null, PropertyType.ENCRYPTEDSTRING, "The token to use to authenticate to Fortify SSC"),
    DEFECTDOJO_ENABLED("integrations", "defectdojo.enabled", "false", PropertyType.BOOLEAN, "Flag to enable/disable DefectDojo integration"),
    DEFECTDOJO_REIMPORT_ENABLED("integrations", "defectdojo.reimport.enabled", "false", PropertyType.BOOLEAN, "Flag to enable/disable DefectDojo reimport-scan API endpoint"),
    DEFECTDOJO_SYNC_CADENCE("integrations", "defectdojo.sync.cadence", "60", PropertyType.INTEGER, "The cadence (in minutes) to upload to DefectDojo"),
    DEFECTDOJO_URL("integrations", "defectdojo.url", null, PropertyType.URL, "Base URL to DefectDojo"),
    DEFECTDOJO_API_KEY("integrations", "defectdojo.apiKey", null, PropertyType.STRING, "API Key for DefectDojo"),
    KENNA_ENABLED("integrations", "kenna.enabled", "false", PropertyType.BOOLEAN, "Flag to enable/disable Kenna Security integration"),
    KENNA_API_URL("integrations", "kenna.api.url", "https://api.kennasecurity.com", PropertyType.STRING, "Kenna Security API URL"),
    KENNA_SYNC_CADENCE("integrations", "kenna.sync.cadence", "60", PropertyType.INTEGER, "The cadence (in minutes) to upload to Kenna Security"),
    KENNA_TOKEN("integrations", "kenna.token", null, PropertyType.ENCRYPTEDSTRING, "The token to use when authenticating to Kenna Security"),
    KENNA_CONNECTOR_ID("integrations", "kenna.connector.id", null, PropertyType.STRING, "The Kenna Security connector identifier to upload to"),
    ACCESS_MANAGEMENT_ACL_ENABLED("access-management", "acl.enabled", "false", PropertyType.BOOLEAN, "Flag to enable/disable access control to projects in the portfolio", true),
    NOTIFICATION_TEMPLATE_BASE_DIR("notification", "template.baseDir", SystemUtils.getEnvironmentVariable("DEFAULT_TEMPLATES_OVERRIDE_BASE_DIRECTORY", System.getProperty("user.home")), PropertyType.STRING, "The base directory to use when searching for notification templates"),
    NOTIFICATION_TEMPLATE_DEFAULT_OVERRIDE_ENABLED("notification", "template.default.override.enabled", SystemUtils.getEnvironmentVariable("DEFAULT_TEMPLATES_OVERRIDE_ENABLED", "false"), PropertyType.BOOLEAN, "Flag to enable/disable override of default notification templates"),
    TASK_SCHEDULER_LDAP_SYNC_CADENCE("task-scheduler", "ldap.sync.cadence", "6", PropertyType.INTEGER, "Sync cadence (in hours) for LDAP"),
    TASK_SCHEDULER_GHSA_MIRROR_CADENCE("task-scheduler", "ghsa.mirror.cadence", "24", PropertyType.INTEGER, "Mirror cadence (in hours) for Github Security Advisories"),
    TASK_SCHEDULER_OSV_MIRROR_CADENCE("task-scheduler", "osv.mirror.cadence", "24", PropertyType.INTEGER, "Mirror cadence (in hours) for OSV database"),
    TASK_SCHEDULER_NIST_MIRROR_CADENCE("task-scheduler", "nist.mirror.cadence", "24", PropertyType.INTEGER, "Mirror cadence (in hours) for NVD database"),
    TASK_SCHEDULER_VULNDB_MIRROR_CADENCE("task-scheduler", "vulndb.mirror.cadence", "24", PropertyType.INTEGER, "Mirror cadence (in hours) for VulnDB database"),
    TASK_SCHEDULER_PORTFOLIO_METRICS_UPDATE_CADENCE("task-scheduler", "portfolio.metrics.update.cadence", "1", PropertyType.INTEGER, "Update cadence (in hours) for portfolio metrics"),
    TASK_SCHEDULER_VULNERABILITY_METRICS_UPDATE_CADENCE("task-scheduler", "vulnerability.metrics.update.cadence", "1", PropertyType.INTEGER, "Update cadence (in hours) for vulnerability metrics"),
    TASK_SCHEDULER_PORTFOLIO_VULNERABILITY_ANALYSIS_CADENCE("task-scheduler", "portfolio.vulnerability.analysis.cadence", "24", PropertyType.INTEGER, "Launch cadence (in hours) for portfolio vulnerability analysis"),
    TASK_SCHEDULER_REPOSITORY_METADATA_FETCH_CADENCE("task-scheduler", "repository.metadata.fetch.cadence", "24", PropertyType.INTEGER, "Metadada fetch cadence (in hours) for package repositories"),
    TASK_SCHEDULER_INTERNAL_COMPONENT_IDENTIFICATION_CADENCE("task-scheduler", "internal.components.identification.cadence", "6", PropertyType.INTEGER, "Internal component identification cadence (in hours)"),
    TASK_SCHEDULER_COMPONENT_ANALYSIS_CACHE_CLEAR_CADENCE("task-scheduler", "component.analysis.cache.clear.cadence", "24", PropertyType.INTEGER, "Cleanup cadence (in hours) for component vulnerability analysis cache"),
    SEARCH_INDEXES_CONSISTENCY_CHECK_ENABLED("search-indexes", "consistency.check.enabled", "true", PropertyType.BOOLEAN, "Flag to enable lucene indexes periodic consistency check"),
    SEARCH_INDEXES_CONSISTENCY_CHECK_CADENCE("search-indexes", "consistency.check.cadence", "4320", PropertyType.INTEGER, "Lucene indexes consistency check cadence (in minutes)"),
    SEARCH_INDEXES_CONSISTENCY_CHECK_DELTA_THRESHOLD("search-indexes", "consistency.check.delta.threshold", "20", PropertyType.INTEGER, "Threshold used to trigger an index rebuild when comparing database table and corresponding lucene index (in percentage). It must be an integer between 1 and 100"),
    BOM_VALIDATION_MODE("artifact", "bom.validation.mode", BomValidationMode.ENABLED.name(), PropertyType.STRING, "Flag to control the BOM validation mode"),
    BOM_VALIDATION_TAGS_INCLUSIVE("artifact", "bom.validation.tags.inclusive", "[]", PropertyType.STRING, "JSON array of tags for which BOM validation shall be performed"),
    BOM_VALIDATION_TAGS_EXCLUSIVE("artifact", "bom.validation.tags.exclusive", "[]", PropertyType.STRING, "JSON array of tags for which BOM validation shall NOT be performed"),
    WELCOME_MESSAGE("general", "welcome.message.html", "%3Chtml%3E%3Ch1%3EYour%20Welcome%20Message%3C%2Fh1%3E%3C%2Fhtml%3E", PropertyType.STRING, "Custom HTML Code that is displayed before login", true),
    IS_WELCOME_MESSAGE("general", "welcome.message.enabled", "false", PropertyType.BOOLEAN, "Bool that says whether to show the welcome message or not", true),
    DEFAULT_LANGUAGE("general", "default.locale", null, PropertyType.STRING, "Determine the default Language to use", true),
    TELEMETRY_SUBMISSION_ENABLED("telemetry", "submission.enabled", String.valueOf(!"true".equals(System.getProperty("dev.mode.enabled")) && Config.getInstance().getPropertyAsBoolean(ConfigKey.TELEMETRY_SUBMISSION_ENABLED_DEFAULT)), PropertyType.BOOLEAN, "Whether submission of telemetry data is enabled"),
    TELEMETRY_LAST_SUBMISSION_DATA("telemetry", "last.submission.data", null, PropertyType.STRING, "Data of the last telemetry submission"),
    TELEMETRY_LAST_SUBMISSION_EPOCH_SECONDS("telemetry", "last.submission.epoch.seconds", null, PropertyType.INTEGER, "Timestamp of the last telemetry submission in epoch seconds");

    private final String groupName;
    private final String propertyName;
    private final String defaultPropertyValue;
    private final PropertyType propertyType;
    private final String description;
    private final Boolean isPublic;

	ConfigPropertyConstants(String groupName, String propertyName, String defaultPropertyValue, PropertyType propertyType, String description) {
        this.groupName = groupName;
        this.propertyName = propertyName;
        this.defaultPropertyValue = defaultPropertyValue;
        this.propertyType = propertyType;
        this.description = description;
        this.isPublic = false;
    }

    ConfigPropertyConstants(String groupName, String propertyName, String defaultPropertyValue, PropertyType propertyType, String description, Boolean isPublic) {
        this.groupName = groupName;
        this.propertyName = propertyName;
        this.defaultPropertyValue = defaultPropertyValue;
        this.propertyType = propertyType;
        this.description = description;
        this.isPublic = isPublic;
    }

    public static ConfigPropertyConstants ofProperty(final IConfigProperty property) {
        return Arrays.stream(values())
                .filter(value -> value.groupName.equals(property.getGroupName()) && value.propertyName.equals(property.getPropertyName()))
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

    public Boolean getIsPublic() {
		    return isPublic;
	  }
}
