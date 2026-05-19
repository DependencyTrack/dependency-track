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
package org.dependencytrack.integrations.defectdojo;

import alpine.model.IConfigProperty;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.model.Project;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import static org.dependencytrack.model.ConfigPropertyConstants.DEFECTDOJO_ENABLED;
import static org.dependencytrack.model.ConfigPropertyConstants.DEFECTDOJO_AUTOCREATE_ENABLED;
import static org.dependencytrack.model.ConfigPropertyConstants.DEFECTDOJO_AUTOCREATE_ENGAGEMENT_NAME;
import static org.dependencytrack.model.ConfigPropertyConstants.DEFECTDOJO_AUTOCREATE_PRODUCT_TYPE_NAME;
import static org.dependencytrack.model.ConfigPropertyConstants.DEFECTDOJO_AUTOCREATE_DEDUPLICATION_ON_ENGAGEMENT;

class DefectDojoUploaderTest extends PersistenceCapableTest {

    @Test
    void testIntegrationMetadata() {
        DefectDojoUploader extension = new DefectDojoUploader();
        Assertions.assertEquals("DefectDojo", extension.name());
        Assertions.assertEquals("Pushes Dependency-Track findings to DefectDojo", extension.description());
    }

    @Test
    void testIntegrationEnabledCases() {
        qm.createConfigProperty(
                DEFECTDOJO_ENABLED.getGroupName(),
                DEFECTDOJO_ENABLED.getPropertyName(),
                "true",
                IConfigProperty.PropertyType.BOOLEAN,
                null
        );
        Project project = qm.createProject("ACME Example", null, "1.0", null, null, null, true, false);
        qm.createProjectProperty(
                project,
                DEFECTDOJO_ENABLED.getGroupName(),
                "defectdojo.engagementId",
                "12345",
                IConfigProperty.PropertyType.STRING,
                null
        );
        DefectDojoUploader extension = new DefectDojoUploader();
        extension.setQueryManager(qm);
        Assertions.assertTrue(extension.isEnabled());
        Assertions.assertTrue(extension.isProjectConfigured(project));
    }

    @Test
    void testIntegrationDisabledCases() {
        Project project = qm.createProject("ACME Example", null, "1.0", null, null, null, true, false);
        DefectDojoUploader extension = new DefectDojoUploader();
        extension.setQueryManager(qm);
        Assertions.assertFalse(extension.isEnabled());
        Assertions.assertFalse(extension.isProjectConfigured(project));
    }

    @Test
    void testAutoCreateEnabled() {
        qm.createConfigProperty(
                DEFECTDOJO_AUTOCREATE_ENABLED.getGroupName(),
                DEFECTDOJO_AUTOCREATE_ENABLED.getPropertyName(),
                "true",
                IConfigProperty.PropertyType.BOOLEAN,
                null
        );
        DefectDojoUploader extension = new DefectDojoUploader();
        extension.setQueryManager(qm);
        Assertions.assertTrue(extension.isAutoCreateEnabled());
    }

    @Test
    void testAutoCreateDisabled() {
        DefectDojoUploader extension = new DefectDojoUploader();
        extension.setQueryManager(qm);
        Assertions.assertFalse(extension.isAutoCreateEnabled());
    }

    @Test
    void testProjectConfiguredWithAutoCreate() {
        qm.createConfigProperty(
                DEFECTDOJO_AUTOCREATE_ENABLED.getGroupName(),
                DEFECTDOJO_AUTOCREATE_ENABLED.getPropertyName(),
                "true",
                IConfigProperty.PropertyType.BOOLEAN,
                null
        );
        Project project = qm.createProject("ACME Example", null, "1.0", null, null, null, true, false);
        DefectDojoUploader extension = new DefectDojoUploader();
        extension.setQueryManager(qm);
        Assertions.assertTrue(extension.isProjectConfigured(project));
    }

    @Test
    void testGetProductNameDefault() {
        Project project = qm.createProject("ACME Example", null, "1.0", null, null, null, true, false);
        DefectDojoUploader extension = new DefectDojoUploader();
        extension.setQueryManager(qm);
        Assertions.assertEquals("ACME Example", extension.getProductName(project));
    }

    @Test
    void testGetProductNameOverride() {
        Project project = qm.createProject("ACME Example", null, "1.0", null, null, null, true, false);
        qm.createProjectProperty(
                project,
                DEFECTDOJO_ENABLED.getGroupName(),
                "defectdojo.autocreate.productName",
                "Custom Product Name",
                IConfigProperty.PropertyType.STRING,
                null
        );
        DefectDojoUploader extension = new DefectDojoUploader();
        extension.setQueryManager(qm);
        Assertions.assertEquals("Custom Product Name", extension.getProductName(project));
    }

    @Test
    void testGetEngagementNameDefault() {
        Project project = qm.createProject("ACME Example", null, "1.0", null, null, null, true, false);
        DefectDojoUploader extension = new DefectDojoUploader();
        extension.setQueryManager(qm);
        Assertions.assertEquals("dependencytrack", extension.getEngagementName(project));
    }

    @Test
    void testGetEngagementNameGlobalConfig() {
        qm.createConfigProperty(
                DEFECTDOJO_AUTOCREATE_ENGAGEMENT_NAME.getGroupName(),
                DEFECTDOJO_AUTOCREATE_ENGAGEMENT_NAME.getPropertyName(),
                "global-engagement",
                IConfigProperty.PropertyType.STRING,
                null
        );
        Project project = qm.createProject("ACME Example", null, "1.0", null, null, null, true, false);
        DefectDojoUploader extension = new DefectDojoUploader();
        extension.setQueryManager(qm);
        Assertions.assertEquals("global-engagement", extension.getEngagementName(project));
    }

    @Test
    void testGetEngagementNameProjectOverride() {
        qm.createConfigProperty(
                DEFECTDOJO_AUTOCREATE_ENGAGEMENT_NAME.getGroupName(),
                DEFECTDOJO_AUTOCREATE_ENGAGEMENT_NAME.getPropertyName(),
                "global-engagement",
                IConfigProperty.PropertyType.STRING,
                null
        );
        Project project = qm.createProject("ACME Example", null, "1.0", null, null, null, true, false);
        qm.createProjectProperty(
                project,
                DEFECTDOJO_ENABLED.getGroupName(),
                "defectdojo.autocreate.engagementName",
                "project-engagement",
                IConfigProperty.PropertyType.STRING,
                null
        );
        DefectDojoUploader extension = new DefectDojoUploader();
        extension.setQueryManager(qm);
        Assertions.assertEquals("project-engagement", extension.getEngagementName(project));
    }

    @Test
    void testGetProductTypeNameDefault() {
        Project project = qm.createProject("ACME Example", null, "1.0", null, null, null, true, false);
        DefectDojoUploader extension = new DefectDojoUploader();
        extension.setQueryManager(qm);
        Assertions.assertEquals("Dependency Track", extension.getProductTypeName(project));
    }

    @Test
    void testGetProductTypeNameGlobalConfig() {
        qm.createConfigProperty(
                DEFECTDOJO_AUTOCREATE_PRODUCT_TYPE_NAME.getGroupName(),
                DEFECTDOJO_AUTOCREATE_PRODUCT_TYPE_NAME.getPropertyName(),
                "Custom Product Type",
                IConfigProperty.PropertyType.STRING,
                null
        );
        Project project = qm.createProject("ACME Example", null, "1.0", null, null, null, true, false);
        DefectDojoUploader extension = new DefectDojoUploader();
        extension.setQueryManager(qm);
        Assertions.assertEquals("Custom Product Type", extension.getProductTypeName(project));
    }

    @Test
    void testGetProductTypeNameProjectOverride() {
        qm.createConfigProperty(
                DEFECTDOJO_AUTOCREATE_PRODUCT_TYPE_NAME.getGroupName(),
                DEFECTDOJO_AUTOCREATE_PRODUCT_TYPE_NAME.getPropertyName(),
                "Global Product Type",
                IConfigProperty.PropertyType.STRING,
                null
        );
        Project project = qm.createProject("ACME Example", null, "1.0", null, null, null, true, false);
        qm.createProjectProperty(
                project,
                DEFECTDOJO_ENABLED.getGroupName(),
                "defectdojo.autocreate.productTypeName",
                "Project Product Type",
                IConfigProperty.PropertyType.STRING,
                null
        );
        DefectDojoUploader extension = new DefectDojoUploader();
        extension.setQueryManager(qm);
        Assertions.assertEquals("Project Product Type", extension.getProductTypeName(project));
    }

    @Test
    void testManualEngagementIdTakesPrecedence() {
        qm.createConfigProperty(
                DEFECTDOJO_AUTOCREATE_ENABLED.getGroupName(),
                DEFECTDOJO_AUTOCREATE_ENABLED.getPropertyName(),
                "true",
                IConfigProperty.PropertyType.BOOLEAN,
                null
        );
        Project project = qm.createProject("ACME Example", null, "1.0", null, null, null, true, false);
        qm.createProjectProperty(
                project,
                DEFECTDOJO_ENABLED.getGroupName(),
                "defectdojo.engagementId",
                "12345",
                IConfigProperty.PropertyType.STRING,
                null
        );
        DefectDojoUploader extension = new DefectDojoUploader();
        extension.setQueryManager(qm);
        // Project should be configured even with auto-create enabled
        Assertions.assertTrue(extension.isProjectConfigured(project));
    }

    @Test
    void testDeduplicationOnEngagementDefault() {
        Project project = qm.createProject("ACME Example", null, "1.0", null, null, null, true, false);
        DefectDojoUploader extension = new DefectDojoUploader();
        extension.setQueryManager(qm);
        Assertions.assertFalse(extension.isDeduplicationOnEngagementEnabled(project));
    }

    @Test
    void testDeduplicationOnEngagementGlobalConfig() {
        qm.createConfigProperty(
                DEFECTDOJO_AUTOCREATE_DEDUPLICATION_ON_ENGAGEMENT.getGroupName(),
                DEFECTDOJO_AUTOCREATE_DEDUPLICATION_ON_ENGAGEMENT.getPropertyName(),
                "true",
                IConfigProperty.PropertyType.BOOLEAN,
                null
        );
        Project project = qm.createProject("ACME Example", null, "1.0", null, null, null, true, false);
        DefectDojoUploader extension = new DefectDojoUploader();
        extension.setQueryManager(qm);
        Assertions.assertTrue(extension.isDeduplicationOnEngagementEnabled(project));
    }

    @Test
    void testDeduplicationOnEngagementProjectOverride() {
        qm.createConfigProperty(
                DEFECTDOJO_AUTOCREATE_DEDUPLICATION_ON_ENGAGEMENT.getGroupName(),
                DEFECTDOJO_AUTOCREATE_DEDUPLICATION_ON_ENGAGEMENT.getPropertyName(),
                "false",
                IConfigProperty.PropertyType.BOOLEAN,
                null
        );
        Project project = qm.createProject("ACME Example", null, "1.0", null, null, null, true, false);
        qm.createProjectProperty(
                project,
                DEFECTDOJO_ENABLED.getGroupName(),
                "defectdojo.autocreate.deduplicationOnEngagement",
                "true",
                IConfigProperty.PropertyType.BOOLEAN,
                null
        );
        DefectDojoUploader extension = new DefectDojoUploader();
        extension.setQueryManager(qm);
        Assertions.assertTrue(extension.isDeduplicationOnEngagementEnabled(project));
    }

}
