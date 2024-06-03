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

import java.util.LinkedHashMap;
import java.util.List;

import org.dependencytrack.model.PolicyViolation;
import org.dependencytrack.model.Project;
import org.junit.Assert;
import org.junit.Test;

public class ScheduledPolicyViolationsIdentifiedTest {
    @Test
    public void testVo() {
        Project project1 = new Project();
        PolicyViolation policyViolation1 = new PolicyViolation();
        PolicyViolation policyViolation2 = new PolicyViolation();
        Project project2 = new Project();
        PolicyViolation policyViolation3 = new PolicyViolation();
        PolicyViolation policyViolation4 = new PolicyViolation();
        PolicyViolation policyViolation5 = new PolicyViolation();
        var projectPolicyViolations = new LinkedHashMap<Project, List<PolicyViolation>>();
        projectPolicyViolations.put(project1, List.of(policyViolation1, policyViolation2));
        projectPolicyViolations.put(project2, List.of(policyViolation3, policyViolation4, policyViolation5));

        ScheduledPolicyViolationsIdentified vo = new ScheduledPolicyViolationsIdentified(projectPolicyViolations);

        Assert.assertEquals(2, vo.getNewProjectPolicyViolations().size());
        Assert.assertEquals(List.of(policyViolation1, policyViolation2), vo.getNewProjectPolicyViolations().get(project1));
        Assert.assertEquals(List.of(policyViolation3, policyViolation4, policyViolation5), vo.getNewProjectPolicyViolations().get(project2));
        Assert.assertEquals(5, vo.getNewPolicyViolationsTotal().size());
        Assert.assertEquals(List.of(policyViolation1, policyViolation2, policyViolation3, policyViolation4, policyViolation5), vo.getNewPolicyViolationsTotal());
    }
}
