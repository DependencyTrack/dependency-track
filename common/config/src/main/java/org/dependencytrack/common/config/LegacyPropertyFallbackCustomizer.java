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
package org.dependencytrack.common.config;

import io.smallrye.config.FallbackConfigSourceInterceptor;
import io.smallrye.config.SmallRyeConfigBuilder;
import io.smallrye.config.SmallRyeConfigBuilderCustomizer;

import java.util.Set;

/**
 * Provides backwards compatibility for config properties that were renamed
 * from {@code alpine.*} or unprefixed names to the {@code dt.*} prefix.
 * <p>
 * When a {@code dt.*} property is looked up and has no value, this interceptor
 * falls back to the legacy property name:
 * <ul>
 *   <li>For properties that historically used the {@code alpine.} prefix
 *       (e.g. {@code alpine.ldap.enabled}): {@code dt.X} falls back to {@code alpine.X}</li>
 *   <li>For all other properties: {@code dt.X} falls back to {@code X} (prefix stripped)</li>
 * </ul>
 *
 * @since 5.0.0
 */
public final class LegacyPropertyFallbackCustomizer implements SmallRyeConfigBuilderCustomizer {

    // Suffixes of properties that historically used the "alpine." prefix.
    static final Set<String> ALPINE_SUFFIXES = Set.of(
            "api.key.prefix",
            "bcrypt.rounds",
            "cors.allow.credentials",
            "cors.allow.headers",
            "cors.allow.methods",
            "cors.allow.origin",
            "cors.enabled",
            "cors.expose.headers",
            "cors.max.age",
            "data.directory",
            "database.password",
            "database.password.file",
            "database.pool.enabled",
            "database.pool.idle.timeout",
            "database.pool.max.lifetime",
            "database.pool.max.size",
            "database.pool.min.idle",
            "database.url",
            "database.username",
            "http.proxy.address",
            "http.proxy.password",
            "http.proxy.password.file",
            "http.proxy.port",
            "http.proxy.username",
            "http.timeout.connection",
            "http.timeout.pool",
            "http.timeout.socket",
            "ldap.attribute.mail",
            "ldap.attribute.name",
            "ldap.auth.username.format",
            "ldap.basedn",
            "ldap.bind.password",
            "ldap.bind.password.file",
            "ldap.bind.username",
            "ldap.enabled",
            "ldap.groups.filter",
            "ldap.groups.search.filter",
            "ldap.security.auth",
            "ldap.server.url",
            "ldap.team.synchronization",
            "ldap.user.groups.filter",
            "ldap.user.provisioning",
            "ldap.users.search.filter",
            "metrics.auth.password",
            "metrics.auth.username",
            "metrics.enabled",
            "no.proxy",
            "oidc.auth.customizer",
            "oidc.client.id",
            "oidc.enabled",
            "oidc.issuer",
            "oidc.team.synchronization",
            "oidc.teams.claim",
            "oidc.teams.default",
            "oidc.user.provisioning",
            "oidc.username.claim",
            "worker.pool.drain.timeout.duration",
            "worker.thread.multiplier",
            "worker.threads"
    );

    @Override
    public void configBuilder(final SmallRyeConfigBuilder builder) {
        builder.withInterceptors(new FallbackConfigSourceInterceptor(name -> {
            // NB: SmallRye Config prefixes property names with "%profile." when
            // a profile is active. Strip it before matching, and re-add it
            // to the fallback name so profiled lookups resolve correctly.
            String profilePrefix = "";
            String lookupName = name;
            if (name.startsWith("%")) {
                final int dotIdx = name.indexOf('.');
                if (dotIdx > 0) {
                    profilePrefix = name.substring(0, dotIdx + 1);
                    lookupName = name.substring(dotIdx + 1);
                }
            }

            if (!lookupName.startsWith("dt.")) {
                return name;
            }

            final String suffix = lookupName.substring("dt.".length());
            if (ALPINE_SUFFIXES.contains(suffix)) {
                return profilePrefix + "alpine." + suffix;
            }

            return profilePrefix + suffix;
        }));
    }

}
