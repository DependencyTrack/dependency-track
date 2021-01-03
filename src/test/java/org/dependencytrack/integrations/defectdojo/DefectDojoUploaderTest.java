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
package org.dependencytrack.integrations.defectdojo;

import alpine.model.IConfigProperty;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.model.Project;
import org.dependencytrack.persistence.QueryManager;
import org.junit.Assert;
import org.junit.Test;
import java.io.InputStream;
import java.util.ArrayList;

import static org.dependencytrack.model.ConfigPropertyConstants.DEFECTDOJO_ENABLED;

public class DefectDojoUploaderTest extends PersistenceCapableTest {

    @Test
    public void testIntegrationMetadata() {
        DefectDojoUploader extension = new DefectDojoUploader();
        Assert.assertEquals("DefectDojo", extension.name());
        Assert.assertEquals("Pushes Dependency-Track findings to DefectDojo", extension.description());
    }

    @Test
    public void testIntegrationEnabledCases() {
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
        Assert.assertTrue(extension.isEnabled());
        Assert.assertTrue(extension.isProjectConfigured(project));
    }

    @Test
    public void testIntegrationDisabledCases() {
        Project project = qm.createProject("ACME Example", null, "1.0", null, null, null, true, false);
        DefectDojoUploader extension = new DefectDojoUploader();
        extension.setQueryManager(qm);
        Assert.assertFalse(extension.isEnabled());
        Assert.assertFalse(extension.isProjectConfigured(project));
    }

    @Test
    public void testIntegrationFindings() throws Exception {
        Project project = qm.createProject("ACME Example", null, "1.0", null, null, null, true, false);
        DefectDojoUploader extension = new DefectDojoUploader();
        extension.setQueryManager(qm);
        InputStream in = extension.process(project, new ArrayList<>());
        Assert.assertTrue(in != null && in.available() > 0);
    }
}
