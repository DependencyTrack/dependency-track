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
package org.dependencytrack.notification.vo;

import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.List;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.scheduled.policyviolations.PolicyViolationDetails;
import org.dependencytrack.model.scheduled.policyviolations.PolicyViolationOverview;
import org.dependencytrack.model.scheduled.policyviolations.PolicyViolationSummary;

public class ScheduledPolicyViolationsIdentified {
    private final PolicyViolationOverview overview;
    private final PolicyViolationSummary summary;
    private final PolicyViolationDetails details;

    public ScheduledPolicyViolationsIdentified(final List<Project> affectedProjects, ZonedDateTime lastExecution) {
        this.overview = new PolicyViolationOverview(affectedProjects, lastExecution.withZoneSameInstant(ZoneOffset.UTC));
        this.summary = new PolicyViolationSummary(affectedProjects, lastExecution.withZoneSameInstant(ZoneOffset.UTC));
        this.details = new PolicyViolationDetails(affectedProjects, lastExecution.withZoneSameInstant(ZoneOffset.UTC));
    }

    public PolicyViolationOverview getOverview() {
        return overview;
    }

    public PolicyViolationSummary getSummary() {
        return summary;
    }

    public PolicyViolationDetails getDetails() {
        return details;
    }
}
