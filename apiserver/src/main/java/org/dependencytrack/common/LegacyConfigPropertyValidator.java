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
package org.dependencytrack.common;

import io.smallrye.config.ConfigValue;
import io.smallrye.config.EnvConfigSource;
import io.smallrye.config.SmallRyeConfig;
import org.eclipse.microprofile.config.Config;

import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

/// Validator of {@link Config} properties to catch usage of legacy properties early.
///
/// Handles three cases of misconfiguration:
///
/// 1. Usage of `*.file` properties instead of `${file::/path}` expressions.
/// 2. Usage of v4 `alpine.*` properties, or well-known properties without `dt.*` prefix in general.
/// 3. Usage of properties that were renamed in 5.0.0-rc.2 for standardization purposes.
///
/// All cases can potentially lead to serious issues that only manifest at runtime.
/// Failing early is both safer and provides better UX (if UX i even be a thing in this context).
///
/// @since 5.0.0
public final class LegacyConfigPropertyValidator {

    static final Set<String> LEGACY_FILE_SECRET_PROPERTIES = Set.of(
            "alpine.database.password.file",
            "alpine.http.proxy.password.file",
            "alpine.ldap.bind.password.file",
            "dt.database.password.file",
            "dt.http.proxy.auth.password.file",
            "dt.http.proxy.password.file",
            "dt.ldap.bind-password.file",
            "dt.ldap.bind.password.file");

    private static final Set<String> LEGACY_V4_PROPERTY_NAMES = Set.of(
            "alpine.api.key.prefix",
            "alpine.bcrypt.rounds",
            "alpine.cors.allow.credentials",
            "alpine.cors.allow.headers",
            "alpine.cors.allow.methods",
            "alpine.cors.allow.origin",
            "alpine.cors.enabled",
            "alpine.cors.expose.headers",
            "alpine.cors.max.age",
            "alpine.data.directory",
            "alpine.database.password",
            "alpine.database.pool.enabled",
            "alpine.database.pool.idle.timeout",
            "alpine.database.pool.max.lifetime",
            "alpine.database.pool.max.size",
            "alpine.database.pool.min.idle",
            "alpine.database.url",
            "alpine.database.username",
            "alpine.http.proxy.address",
            "alpine.http.proxy.password",
            "alpine.http.proxy.port",
            "alpine.http.proxy.username",
            "alpine.http.timeout.connection",
            "alpine.http.timeout.pool",
            "alpine.http.timeout.socket",
            "alpine.ldap.attribute.mail",
            "alpine.ldap.attribute.name",
            "alpine.ldap.auth.username.format",
            "alpine.ldap.basedn",
            "alpine.ldap.bind.password",
            "alpine.ldap.bind.username",
            "alpine.ldap.enabled",
            "alpine.ldap.groups.filter",
            "alpine.ldap.groups.search.filter",
            "alpine.ldap.security.auth",
            "alpine.ldap.server.url",
            "alpine.ldap.team.synchronization",
            "alpine.ldap.user.groups.filter",
            "alpine.ldap.user.provisioning",
            "alpine.ldap.users.search.filter",
            "alpine.metrics.auth.password",
            "alpine.metrics.auth.username",
            "alpine.metrics.enabled",
            "alpine.no.proxy",
            "alpine.oidc.auth.customizer",
            "alpine.oidc.client.id",
            "alpine.oidc.enabled",
            "alpine.oidc.issuer",
            "alpine.oidc.team.synchronization",
            "alpine.oidc.teams.claim",
            "alpine.oidc.teams.default",
            "alpine.oidc.user.provisioning",
            "alpine.oidc.username.claim",
            "alpine.worker.thread.multiplier",
            "alpine.worker.threads");

    static final Map<String, String> LEGACY_V5_RC1_PROPERTY_RENAMES = buildLegacyV5Rc1Renames();

    private LegacyConfigPropertyValidator() {
    }

    public static void validate(Config config) {
        final SmallRyeConfig smallRyeConfig = config.unwrap(SmallRyeConfig.class);

        throwOnLegacyFileSecretProperties(smallRyeConfig);
        throwOnLegacyV4Properties(smallRyeConfig);
        throwOnLegacyV5Rc1Properties(smallRyeConfig);
    }

    private static void throwOnLegacyFileSecretProperties(SmallRyeConfig config) {
        final var present = new HashSet<String>();
        for (final String name : LEGACY_FILE_SECRET_PROPERTIES) {
            if (config.getOptionalValue(name, String.class).isPresent()) {
                present.add(name);
            }
        }
        if (present.isEmpty()) {
            return;
        }

        throw new IllegalStateException("""
                Legacy file-secret properties are no longer supported: %s; \
                Replace each <key>.file=/path with <key>=${file::/path}\
                """.formatted(present));
    }

    private static void throwOnLegacyV4Properties(SmallRyeConfig config) {
        final var present = new HashSet<String>();
        for (final String name : LEGACY_V4_PROPERTY_NAMES) {
            if (config.getOptionalValue(name, String.class).isPresent()) {
                present.add(name);
            }
        }
        if (present.isEmpty()) {
            return;
        }

        throw new IllegalStateException("""
                Legacy Dependency-Track v4 configuration properties are no longer supported: %s; \
                Migrate to the dt.* equivalents documented in the v5.0.0-rc.2 upgrade guide: \
                https://dependencytrack.github.io/docs/next/guides/upgrading/v5.0.0-rc.2/\
                """.formatted(present));
    }

    private static void throwOnLegacyV5Rc1Properties(SmallRyeConfig config) {
        final var present = new LinkedHashMap<String, String>();
        LEGACY_V5_RC1_PROPERTY_RENAMES.forEach((oldName, newName) -> {
            // NB: Env vars treat `.` and `-` as identical, so renames that only swap
            // `.` and `-` (e.g. `dt.task.tag.maintenance.cron` -> `dt.task.tag-maintenance.cron`)
            // share an env-var form. When the value came from EnvConfigSource and the env names collide,
            // the user is setting the canonical name via env var, not the legacy form.
            final ConfigValue configValue = config.getConfigValue(oldName);
            if (configValue.getValue() != null
                    && (!configValue.getSourceName().startsWith(EnvConfigSource.NAME)
                            || !envForm(oldName).equals(envForm(newName)))) {
                present.put(oldName, newName);
            }

            // We previously aliased `dt.X` to `X`. Make sure the latter is also recognized.
            final String bareName = oldName.substring("dt.".length());
            if (config.getConfigValue(bareName).getValue() != null) {
                present.put(bareName, newName);
            }
        });
        if (present.isEmpty()) {
            return;
        }

        final var migrations = new StringBuilder();
        present.forEach((oldName, newName) ->
                migrations.append("\n  ").append(oldName).append(" -> ").append(newName));

        throw new IllegalStateException("""
                Legacy Dependency-Track v5.0.0-rc.1 configuration properties are no longer supported. \
                Rename the following properties to their v5.0.0-rc.2 equivalents (see \
                https://dependencytrack.github.io/docs/next/guides/upgrading/v5.0.0-rc.2/):%s\
                """.formatted(migrations));
    }

    private static String envForm(String name) {
        return name.toUpperCase(Locale.ROOT).replace('.', '_').replace('-', '_');
    }

    private static Map<String, String> buildLegacyV5Rc1Renames() {
        final var renames = new TreeMap<String, String>();
        renames.put("dt.api.key.prefix", "dt.api-key.prefix");
        renames.put("dt.config.log.values", "dt.config.log-values");
        renames.put("dt.cors.allow.credentials", "dt.cors.allow-credentials");
        renames.put("dt.cors.allow.headers", "dt.cors.allowed-headers");
        renames.put("dt.cors.allow.methods", "dt.cors.allowed-methods");
        renames.put("dt.cors.allow.origin", "dt.cors.allowed-origins");
        renames.put("dt.cors.expose.headers", "dt.cors.exposed-headers");
        renames.put("dt.cors.max.age", "dt.cors.max-age");
        renames.put("dt.data.directory", "dt.data-directory");
        renames.put("dt.dev.services.enabled", "dt.dev-services.enabled");
        renames.put("dt.dev.services.image.frontend", "dt.dev-services.frontend-image");
        renames.put("dt.dev.services.image.postgres", "dt.dev-services.postgres-image");
        renames.put("dt.dev.services.port.frontend", "dt.dev-services.frontend-port");
        renames.put("dt.dex-engine.maintenance-worker.initial-delay-ms", "dt.dex-engine.maintenance.worker-initial-delay-ms");
        renames.put("dt.dex-engine.maintenance-worker.interval-ms", "dt.dex-engine.maintenance.worker-interval-ms");
        renames.put("dt.dex-engine.maintenance.run-retention-duration", "dt.dex-engine.maintenance.run-retention-ms (now a long in milliseconds, was an ISO-8601 Duration)");
        renames.put("dt.dex-engine.maintenance.worker.initial-delay-ms", "dt.dex-engine.maintenance.worker-initial-delay-ms");
        renames.put("dt.dex-engine.maintenance.worker.interval-ms", "dt.dex-engine.maintenance.worker-interval-ms");
        renames.put("dt.dex-engine.metrics.collector.enabled", "dt.dex-engine.metrics-collector.enabled");
        renames.put("dt.dex-engine.metrics.collector.initial-delay-ms", "dt.dex-engine.metrics-collector.initial-delay-ms");
        renames.put("dt.dex-engine.metrics.collector.interval-ms", "dt.dex-engine.metrics-collector.interval-ms");
        renames.put("dt.file-storage.local.compression.level", "dt.file-storage.local.compression-level");
        renames.put("dt.file-storage.s3.access.key", "dt.file-storage.s3.access-key");
        renames.put("dt.file-storage.s3.compression.level", "dt.file-storage.s3.compression-level");
        renames.put("dt.file-storage.s3.secret.key", "dt.file-storage.s3.secret-key");
        renames.put("dt.http.proxy.address", "dt.http.proxy.host");
        renames.put("dt.http.proxy.password", "dt.http.proxy.auth.password");
        renames.put("dt.http.proxy.username", "dt.http.proxy.auth.username");
        renames.put("dt.http.timeout.connection", "dt.http.connect-timeout-ms (now milliseconds, was seconds)");
        renames.put("dt.init.and.exit", "dt.init-tasks.exit-after-completion");
        renames.put("dt.init.task.database.migration.enabled", "dt.init-task.database-migration.enabled");
        renames.put("dt.init.task.database.partition.maintenance.enabled", "dt.init-task.database-partition-maintenance.enabled");
        renames.put("dt.init.task.database.seeding.enabled", "dt.init-task.database-seeding.enabled");
        renames.put("dt.init.task.dex.engine.database.migration.enabled", "dt.init-task.dex-engine-database-migration.enabled");
        renames.put("dt.init.task.key.generation.enabled", "(removed; key generation no longer runs as an init task)");
        renames.put("dt.init.tasks.datasource.close-after-use", "dt.init-tasks.datasource.close-after-completion");
        renames.put("dt.init.tasks.datasource.name", "dt.init-tasks.datasource.name");
        renames.put("dt.init.tasks.enabled", "dt.init-tasks.enabled");
        renames.put("dt.ldap.attribute.mail", "dt.ldap.mail-attribute");
        renames.put("dt.ldap.attribute.name", "dt.ldap.name-attribute");
        renames.put("dt.ldap.auth.username.format", "dt.ldap.username-format");
        renames.put("dt.ldap.basedn", "dt.ldap.base-dn");
        renames.put("dt.ldap.bind.password", "dt.ldap.bind-password");
        renames.put("dt.ldap.bind.username", "dt.ldap.bind-username");
        renames.put("dt.ldap.groups.filter", "dt.ldap.group-filter");
        renames.put("dt.ldap.groups.search.filter", "dt.ldap.group-search-filter");
        renames.put("dt.ldap.security.auth", "dt.ldap.security-auth");
        renames.put("dt.ldap.server.url", "dt.ldap.server-url");
        renames.put("dt.ldap.team.synchronization", "dt.ldap.team-synchronization");
        renames.put("dt.ldap.user.groups.filter", "dt.ldap.user-groups-filter");
        renames.put("dt.ldap.user.provisioning", "dt.ldap.user-provisioning");
        renames.put("dt.ldap.users.search.filter", "dt.ldap.user-search-filter");
        renames.put("dt.no.proxy", "dt.http.proxy.exclusions");
        renames.put("dt.oidc.auth.customizer", "dt.oidc.auth-customizer");
        renames.put("dt.oidc.client.id", "dt.oidc.client-id");
        renames.put("dt.oidc.team.synchronization", "dt.oidc.team-synchronization");
        renames.put("dt.oidc.teams.claim", "dt.oidc.teams-claim");
        renames.put("dt.oidc.teams.default", "dt.oidc.default-teams");
        renames.put("dt.oidc.user.provisioning", "dt.oidc.user-provisioning");
        renames.put("dt.oidc.username.claim", "dt.oidc.username-claim");
        renames.put("dt.task.defect.dojo.upload.cron", "dt.task.defect-dojo-upload.cron");
        renames.put("dt.task.epss.mirror.cron", "dt.task.epss-mirror.cron");
        renames.put("dt.task.fortify.ssc.upload.cron", "dt.task.fortify-ssc-upload.cron");
        renames.put("dt.task.git.hub.advisory.mirror.cron", "dt.task.github-advisory-vuln-data-source-mirror.cron");
        renames.put("dt.task.kenna.security.upload.cron", "dt.task.kenna-security-upload.cron");
        renames.put("dt.task.metrics.maintenance.cron", "dt.task.metrics-maintenance.cron");
        renames.put("dt.task.nist.mirror.cron", "dt.task.nvd-vuln-data-source-mirror.cron");
        renames.put("dt.task.osv.mirror.cron", "dt.task.osv-vuln-data-source-mirror.cron");
        renames.put("dt.task.package.metadata.maintenance.cron", "dt.task.package-metadata-maintenance.cron");
        renames.put("dt.task.project.maintenance.cron", "dt.task.project-maintenance.cron");
        renames.put("dt.task.tag.maintenance.cron", "dt.task.tag-maintenance.cron");
        renames.put("dt.task.vulnerability-policy-bundle-sync.cron", "dt.task.vuln-policy-bundle-sync.cron");
        renames.put("dt.task.vulnerability.analysis.cron", "dt.task.portfolio-analysis.cron");
        renames.put("dt.task.vulnerability.database.maintenance.cron", "dt.task.vuln-database-maintenance.cron");
        renames.put("dt.task.vulnerability.metrics.update.cron", "dt.task.vuln-metrics-update.cron");
        renames.put("dt.telemetry.submission.enabled.default", "dt.telemetry.submission.default-enabled");
        renames.put("dt.tmp.delay.bom.processed.notification", "dt.tmp.delay-bom-processed-notification");
        renames.put("dt.vulnerability.policy.bundle.auth.bearer.token", "dt.vuln-policy-bundle.auth.bearer-token");
        renames.put("dt.vulnerability.policy.bundle.auth.password", "dt.vuln-policy-bundle.auth.password");
        renames.put("dt.vulnerability.policy.bundle.auth.username", "dt.vuln-policy-bundle.auth.username");
        renames.put("dt.vulnerability.policy.bundle.url", "dt.vuln-policy-bundle.url");
        return renames;
    }

}
