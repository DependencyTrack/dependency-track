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
package org.dependencytrack.secret.management.env;

import org.dependencytrack.common.pagination.PageTokenEncoder;
import org.dependencytrack.secret.management.SecretManager;
import org.dependencytrack.secret.management.SecretManagerProvider;
import org.eclipse.microprofile.config.Config;
import org.slf4j.LoggerFactory;

import java.util.HashMap;
import java.util.Map;

/**
 * @since 5.0.0
 */
public final class EnvSecretManagerProvider implements SecretManagerProvider {

    private final Map<String, String> env;

    EnvSecretManagerProvider(Map<String, String> env) {
        this.env = env;
    }

    @SuppressWarnings("unused") // Used by ServiceLoader.
    public EnvSecretManagerProvider() {
        this(System.getenv());
    }

    @Override
    public String name() {
        return "env";
    }

    @Override
    public SecretManager create(Config config, PageTokenEncoder pageTokenEncoder) {
        final var logger = LoggerFactory.getLogger(EnvSecretManager.class);
        final var secretValueByName = new HashMap<String, String>();

        for (final Map.Entry<String, String> envEntry : env.entrySet()) {
            final String envName = envEntry.getKey();
            final String envValue = envEntry.getValue();

            if (!envName.toLowerCase().startsWith("dt_secret_")) {
                continue;
            }

            final String secretName = envName.substring(10);
            if (!SecretManager.VALID_NAME_PATTERN.matcher(secretName).matches()) {
                logger.warn("""
                        Environment variable {} has the secret prefix, \
                        but does not match the valid secret name pattern {}\
                        """, envName, SecretManager.VALID_NAME_PATTERN.pattern());
                continue;
            }

            secretValueByName.put(secretName, envValue);
        }

        if (secretValueByName.isEmpty()) {
            logger.warn("No secrets found");
        } else {
            for (final String secretName : secretValueByName.keySet()) {
                logger.info("Picked up secret: {}", secretName);
            }
        }

        return new EnvSecretManager(secretValueByName, pageTokenEncoder);
    }

}
