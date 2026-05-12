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
package org.dependencytrack.v4migrator.config;

import picocli.CommandLine.Option;

/**
 * Mixin for commands that initiate extraction. v4 has no concept of metrics retention;
 * v5 introduces it. The operator must make an explicit choice rather than have the migrator
 * silently drop or carry over metrics rows. Use {@code 0} to drop all metrics, a positive
 * integer to keep {@code N} days, or a very large number to migrate every row (which will
 * pre-create one daily partition per retained day).
 */
public final class MetricsRetentionOptions {

    @Option(names = "--metrics-retention-days",
        description = "DEPENDENCYMETRICS / PROJECTMETRICS retention window. v4 had no retention "
            + "concept; you must decide explicitly. 0 drops all metrics; N > 0 keeps the last N "
            + "days. Large values pre-create one daily partition per retained day.",
        required = true)
    public int metricsRetentionDays;
}