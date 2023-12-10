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
package org.dependencytrack.persistence;

import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.model.Classifier;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Policy;
import org.dependencytrack.model.PolicyViolation;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.ViolationAnalysis;
import org.dependencytrack.model.ViolationAnalysisComment;
import org.dependencytrack.model.ViolationAnalysisState;
import org.junit.Test;
import org.junit.Assert;

import com.github.packageurl.PackageURL;
import com.github.packageurl.PackageURLBuilder;

import ch.qos.logback.core.subst.Token.Type;
import us.springett.parsers.cpe.Cpe;
import us.springett.parsers.cpe.CpeParser;
import us.springett.parsers.cpe.exceptions.CpeParsingException;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import javax.jdo.PersistenceManager;

import static java.util.Collections.newSetFromMap;
import static org.assertj.core.api.Assertions.assertThat;

public class PolicyQueryManagerTest extends PersistenceCapableTest {

    @Test
    public void testRemoveProjectFromPolicies() {
        final Project project = qm.createProject("ACME Example", null, "1.0", null, null, null, true, false);

        // Create multiple policies that all reference the project
        final Policy policy1 = qm.createPolicy("Test Policy 1", Policy.Operator.ANY, Policy.ViolationState.INFO);
        policy1.setProjects(List.of(project));
        qm.persist(policy1);
        final Policy policy2 = qm.createPolicy("Test Policy 2", Policy.Operator.ANY, Policy.ViolationState.INFO);
        policy2.setProjects(List.of(project));
        qm.persist(policy2);

        // Remove project from all policies and verify that the associations have indeed been cleared
        qm.removeProjectFromPolicies(project);
        assertThat(qm.getObjectById(Policy.class, policy1.getId()).getProjects()).isEmpty();
        assertThat(qm.getObjectById(Policy.class, policy2.getId()).getProjects()).isEmpty();
    }

    @Test
    public void testclonePolicyViolation() throws Exception{
        PolicyViolation policyViolation = new PolicyViolation();
        policyViolation.setId(1);

        // Component for cloning
        Component component = new Component();
        component.setId(111L);
        component.setName("name");
        component.setVersion("1.0");
        component.setCopyright("Copyright Acme");
        
        policyViolation.setComponent(component);
        policyViolation.setText("policyViolation");
        policyViolation.setTimestamp(new Date());
        policyViolation.setType(PolicyViolation.Type.LICENSE);

        // ViolationAnalysis for cloning
        ViolationAnalysis violationAnalysis = new ViolationAnalysis();
        violationAnalysis.setSuppressed(true);
        violationAnalysis.setViolationAnalysisState(ViolationAnalysisState.APPROVED);

        // ViolationAnalysisComments
        List<ViolationAnalysisComment> violationAnalysisComments = new ArrayList<>();
        ViolationAnalysisComment violationAnalysisComment = new ViolationAnalysisComment();
        violationAnalysisComment.setComment("testComment");
        violationAnalysisComment.setCommenter("admin");
        violationAnalysisComment.setTimestamp(new Date());
        violationAnalysisComment.setViolationAnalysis(violationAnalysis);
        violationAnalysisComments.add(violationAnalysisComment);
        violationAnalysis.setAnalysisComments(violationAnalysisComments);

        policyViolation.setAnalysis(violationAnalysis);

        PolicyViolation clonedPolicyViolation = qm.clonePolicyViolation(policyViolation, component);
        Assert.assertEquals(policyViolation.getText(), clonedPolicyViolation.getText());
        Assert.assertEquals(policyViolation.getType(), clonedPolicyViolation.getType());
        Assert.assertEquals(policyViolation.getTimestamp(), clonedPolicyViolation.getTimestamp());
        Assert.assertEquals(policyViolation.getAnalysis().isSuppressed(), clonedPolicyViolation.getAnalysis().isSuppressed());
        Assert.assertEquals(policyViolation.getAnalysis().getAnalysisState(), clonedPolicyViolation.getAnalysis().getAnalysisState());
        Assert.assertEquals(policyViolation.getAnalysis().getAnalysisComments().get(0).getComment(), clonedPolicyViolation.getAnalysis().getAnalysisComments().get(0).getComment());
        Assert.assertEquals(policyViolation.getAnalysis().getAnalysisComments().get(0).getCommenter(), clonedPolicyViolation.getAnalysis().getAnalysisComments().get(0).getCommenter());
        Assert.assertEquals(policyViolation.getAnalysis().getAnalysisComments().get(0).getTimestamp(), clonedPolicyViolation.getAnalysis().getAnalysisComments().get(0).getTimestamp());
        Assert.assertEquals(policyViolation.getComponent().getId(), clonedPolicyViolation.getComponent().getId());
        Assert.assertEquals(policyViolation.getComponent().getName(), clonedPolicyViolation.getComponent().getName());
        Assert.assertEquals(policyViolation.getComponent().getCopyright(), clonedPolicyViolation.getComponent().getCopyright());
        Assert.assertEquals(policyViolation.getComponent().getVersion(), clonedPolicyViolation.getComponent().getVersion());
    }

}