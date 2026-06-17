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
package org.dependencytrack.policy.cel.compat;

import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.License;
import org.dependencytrack.model.LicenseGroup;
import org.dependencytrack.model.Policy;
import org.dependencytrack.model.PolicyCondition;
import org.dependencytrack.model.Project;
import org.dependencytrack.policy.cel.CelPolicyEngine;
import org.junit.jupiter.api.Test;

import java.util.Collections;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

public class LicenseGroupConditionTest extends PersistenceCapableTest {

    @Test
    public void hasMatch() {
        License license = new License();
        license.setName("Apache 2.0");
        license.setUuid(UUID.randomUUID());
        license = qm.persist(license);
        LicenseGroup lg = qm.createLicenseGroup("Test License Group");
        lg.setLicenses(Collections.singletonList(license));
        lg = qm.persist(lg);

        Policy policy = qm.createPolicy("Test Policy", Policy.Operator.ANY, Policy.ViolationState.INFO);
        PolicyCondition condition = qm.createPolicyCondition(policy, PolicyCondition.Subject.LICENSE_GROUP, PolicyCondition.Operator.IS, lg.getUuid().toString());

        qm.detach(Policy.class, policy.getId());
        qm.detach(PolicyCondition.class, condition.getId());

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var component = new Component();
        component.setName("acme-app");
        component.setResolvedLicense(license);
        component.setProject(project);
        qm.persist(component);

        new CelPolicyEngine().evaluateProject(project.getUuid());
        assertThat(qm.getAllPolicyViolations(component)).hasSize(1);
    }

    @Test
    public void noMatch() {
        License license = new License();
        license.setName("Apache 2.0");
        license.setUuid(UUID.randomUUID());
        license = qm.persist(license);
        LicenseGroup lg = qm.createLicenseGroup("Test License Group");
        lg = qm.persist(lg);

        Policy policy = qm.createPolicy("Test Policy", Policy.Operator.ANY, Policy.ViolationState.INFO);
        PolicyCondition condition = qm.createPolicyCondition(policy, PolicyCondition.Subject.LICENSE_GROUP, PolicyCondition.Operator.IS, lg.getUuid().toString());
        qm.detach(Policy.class, policy.getId());
        qm.detach(PolicyCondition.class, condition.getId());

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var component = new Component();
        component.setName("acme-app");
        component.setResolvedLicense(license);
        component.setProject(project);
        qm.persist(component);

        new CelPolicyEngine().evaluateProject(project.getUuid());
        assertThat(qm.getAllPolicyViolations(component)).isEmpty();
    }

    @Test
    public void unknownLicenseViolateWhitelist() {
        LicenseGroup lg = qm.createLicenseGroup("Test License Group");
        lg = qm.persist(lg);
        lg = qm.detach(LicenseGroup.class, lg.getId());
        Policy policy = qm.createPolicy("Test Policy", Policy.Operator.ANY, Policy.ViolationState.INFO);
        PolicyCondition condition = qm.createPolicyCondition(policy, PolicyCondition.Subject.LICENSE_GROUP, PolicyCondition.Operator.IS_NOT, lg.getUuid().toString());
        qm.detach(Policy.class, policy.getId());
        qm.detach(PolicyCondition.class, condition.getId());

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var component = new Component();
        component.setName("acme-app");
        component.setResolvedLicense(null);
        component.setProject(project);
        qm.persist(component);

        new CelPolicyEngine().evaluateProject(project.getUuid());
        assertThat(qm.getAllPolicyViolations(component)).hasSize(1);
    }

    @Test
    public void wrongOperator() {
        License license = new License();
        license.setName("Apache 2.0");
        license.setLicenseId("Apache-2.0");
        license.setUuid(UUID.randomUUID());
        license = qm.persist(license);
        LicenseGroup lg = qm.createLicenseGroup("Test License Group");
        lg.setLicenses(Collections.singletonList(license));
        lg = qm.persist(lg);
        Policy policy = qm.createPolicy("Test Policy", Policy.Operator.ANY, Policy.ViolationState.INFO);
        qm.createPolicyCondition(policy, PolicyCondition.Subject.LICENSE_GROUP, PolicyCondition.Operator.MATCHES, lg.getUuid().toString());
        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var component = new Component();
        component.setName("acme-app");
        component.setResolvedLicense(license);
        component.setProject(project);
        qm.persist(component);

        new CelPolicyEngine().evaluateProject(project.getUuid());
        assertThat(qm.getAllPolicyViolations(component)).isEmpty();
    }

    @Test
    void shouldMatchLicenseGroupByLicenseExpression() {
        final var mit = new License();
        mit.setName("MIT License");
        mit.setLicenseId("MIT");
        mit.setUuid(UUID.randomUUID());
        qm.persist(mit);
        LicenseGroup lg = qm.createLicenseGroup("Permissive");
        lg.setLicenses(Collections.singletonList(mit));
        lg = qm.persist(lg);

        final Policy policy = qm.createPolicy("Test Policy", Policy.Operator.ANY, Policy.ViolationState.INFO);
        qm.createPolicyCondition(policy, PolicyCondition.Subject.LICENSE_GROUP, PolicyCondition.Operator.IS, lg.getUuid().toString());

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var component = new Component();
        component.setName("acme-app");
        component.setLicenseExpression("MIT");
        component.setProject(project);
        qm.persist(component);

        new CelPolicyEngine().evaluateProject(project.getUuid());
        assertThat(qm.getAllPolicyViolations(component)).hasSize(1);
    }

    @Test
    void shouldMatchLicenseGroupByLicenseName() {
        final var mit = new License();
        mit.setName("MIT License");
        mit.setLicenseId("MIT");
        mit.setUuid(UUID.randomUUID());
        qm.persist(mit);
        LicenseGroup lg = qm.createLicenseGroup("Permissive");
        lg.setLicenses(Collections.singletonList(mit));
        lg = qm.persist(lg);

        final Policy policy = qm.createPolicy("Test Policy", Policy.Operator.ANY, Policy.ViolationState.INFO);
        qm.createPolicyCondition(policy, PolicyCondition.Subject.LICENSE_GROUP, PolicyCondition.Operator.IS, lg.getUuid().toString());

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var component = new Component();
        component.setName("acme-app");
        component.setLicense("MIT");
        component.setProject(project);
        qm.persist(component);

        new CelPolicyEngine().evaluateProject(project.getUuid());
        assertThat(qm.getAllPolicyViolations(component)).hasSize(1);
    }

    @Test
    void shouldNotViolateIsNotWhenOrExpressionPermitsGroupMember() {
        final var mit = new License();
        mit.setName("MIT License");
        mit.setLicenseId("MIT");
        mit.setUuid(UUID.randomUUID());
        qm.persist(mit);
        LicenseGroup lg = qm.createLicenseGroup("Permissive");
        lg.setLicenses(Collections.singletonList(mit));
        lg = qm.persist(lg);

        final Policy policy = qm.createPolicy("Test Policy", Policy.Operator.ANY, Policy.ViolationState.INFO);
        qm.createPolicyCondition(policy, PolicyCondition.Subject.LICENSE_GROUP, PolicyCondition.Operator.IS_NOT, lg.getUuid().toString());

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var component = new Component();
        component.setName("acme-app");
        component.setLicenseExpression("MIT OR Apache-2.0");
        component.setProject(project);
        qm.persist(component);

        new CelPolicyEngine().evaluateProject(project.getUuid());
        assertThat(qm.getAllPolicyViolations(component)).isEmpty();
    }

    @Test
    void shouldViolateIsWhenAndExpressionContainsGroupMember() {
        final var gpl = new License();
        gpl.setName("GNU General Public License v2.0");
        gpl.setLicenseId("GPL-2.0");
        gpl.setUuid(UUID.randomUUID());
        qm.persist(gpl);
        LicenseGroup lg = qm.createLicenseGroup("Copyleft");
        lg.setLicenses(Collections.singletonList(gpl));
        lg = qm.persist(lg);

        final Policy policy = qm.createPolicy("Test Policy", Policy.Operator.ANY, Policy.ViolationState.INFO);
        qm.createPolicyCondition(policy, PolicyCondition.Subject.LICENSE_GROUP, PolicyCondition.Operator.IS, lg.getUuid().toString());

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var component = new Component();
        component.setName("acme-app");
        component.setLicenseExpression("MIT AND GPL-2.0");
        component.setProject(project);
        qm.persist(component);

        new CelPolicyEngine().evaluateProject(project.getUuid());
        assertThat(qm.getAllPolicyViolations(component)).hasSize(1);
    }

    @Test
    public void licenseGroupDoesNotExist() {
        License license = new License();
        license.setName("Apache 2.0");
        license.setLicenseId("Apache-2.0");
        license.setUuid(UUID.randomUUID());
        license = qm.persist(license);
        Policy policy = qm.createPolicy("Test Policy", Policy.Operator.ANY, Policy.ViolationState.INFO);
        PolicyCondition condition = qm.createPolicyCondition(policy, PolicyCondition.Subject.LICENSE_GROUP, PolicyCondition.Operator.IS, UUID.randomUUID().toString());
        qm.detach(Policy.class, policy.getId());
        qm.detach(PolicyCondition.class, condition.getId());
        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var component = new Component();
        component.setName("acme-app");
        component.setResolvedLicense(license);
        component.setProject(project);
        qm.persist(component);

        new CelPolicyEngine().evaluateProject(project.getUuid());
        assertThat(qm.getAllPolicyViolations(component)).isEmpty();
    }
}
