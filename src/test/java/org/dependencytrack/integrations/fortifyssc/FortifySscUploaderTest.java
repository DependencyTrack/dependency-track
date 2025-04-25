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
package org.dependencytrack.integrations.fortifyssc;

import alpine.model.IConfigProperty;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.model.Project;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.util.ArrayList;

import static org.dependencytrack.model.ConfigPropertyConstants.FORTIFY_SSC_ENABLED;

class FortifySscUploaderTest extends PersistenceCapableTest {
    @Test
    void testIntegrationMetadata() {
        FortifySscUploader extension = new FortifySscUploader();
        Assertions.assertEquals("Fortify SSC", extension.name());
        Assertions.assertEquals("Pushes Dependency-Track findings to Software Security Center", extension.description());
    }

    @Test
    void testIntegrationEnabledCases() {
        qm.createConfigProperty(
                FORTIFY_SSC_ENABLED.getGroupName(),
                FORTIFY_SSC_ENABLED.getPropertyName(),
                "true",
                IConfigProperty.PropertyType.BOOLEAN,
                null
        );
        Project project = qm.createProject("ACME Example", null, "1.0", null, null, null, true, false);
        qm.createProjectProperty(
                project,
                FORTIFY_SSC_ENABLED.getGroupName(),
                "fortify.ssc.applicationId",
                "12345",
                IConfigProperty.PropertyType.STRING,
                null
        );
        FortifySscUploader extension = new FortifySscUploader();
        extension.setQueryManager(qm);
        Assertions.assertTrue(extension.isEnabled());
        Assertions.assertTrue(extension.isProjectConfigured(project));
    }

    @Test
    void testIntegrationDisabledCases() {
        Project project = qm.createProject("ACME Example", null, "1.0", null, null, null, true, false);
        FortifySscUploader extension = new FortifySscUploader();
        extension.setQueryManager(qm);
        Assertions.assertFalse(extension.isEnabled());
        Assertions.assertFalse(extension.isProjectConfigured(project));
    }

    @Test
    void testIntegrationFindings() throws Exception {
        Project project = qm.createProject("ACME Example", null, "1.0", null, null, null, true, false);
        FortifySscUploader extension = new FortifySscUploader();
        extension.setQueryManager(qm);
        InputStream in = extension.process(project, new ArrayList<>());
        Assertions.assertTrue(in != null && in.available() > 0);
    }
}
