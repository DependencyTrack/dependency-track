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
package org.dependencytrack.persistence.jdbi.command;

import java.util.UUID;

/**
 * @since 5.0.0
 */
public record CloneProjectCommand(
        UUID sourceProjectUuid,
        String targetProjectVersion,
        boolean targetProjectVersionIsLatest,
        boolean includeAcl,
        boolean includeComponents,
        boolean includeFindings,
        boolean includeFindingsAuditHistory,
        boolean includePolicyViolations,
        boolean includePolicyViolationsAuditHistory,
        boolean includeProperties,
        boolean includeServices,
        boolean includeTags) {
}
