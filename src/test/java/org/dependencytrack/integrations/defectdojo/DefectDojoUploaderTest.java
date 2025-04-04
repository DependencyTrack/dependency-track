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

}
