/*
 * Copyright 2022 OWASP.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.dependencytrack.task;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.event.BomUploadEvent;
import org.dependencytrack.model.Classifier;
import org.dependencytrack.model.ConfigPropertyConstants;
import org.dependencytrack.model.Project;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.tasks.BomUploadProcessingTask;
import org.junit.Assert;
import org.junit.Test;

public class BomUploadProcessingTaskTest extends PersistenceCapableTest {

    @Test
    public void informTest() throws IOException {
        final var task = new BomUploadProcessingTask();
        final var bom = new File(Thread.currentThread().getContextClassLoader().getResource("bom-1.xml").getFile());
        final var project = qm.createProject("test-project", null, "test", null, null, null, true, false);
        final var uploadEvent = new BomUploadEvent(project.getUuid(), Files.readAllBytes(bom.toPath()));
        final var acceptArtifactProp = ConfigPropertyConstants.ACCEPT_ARTIFACT_CYCLONEDX;
        qm.createConfigProperty(acceptArtifactProp.getGroupName(), acceptArtifactProp.getPropertyName(), "true", acceptArtifactProp.getPropertyType(), acceptArtifactProp.getDescription());

        task.inform(uploadEvent);

        // task uses own QueryManager so we can not reuse the global qm from the test
        try (var qm2 = new QueryManager()) {
            final var updatedProject = qm2.getObjectById(Project.class, project.getId());
            Assert.assertEquals(Classifier.APPLICATION, updatedProject.getClassifier());
            Assert.assertNotNull(updatedProject.getLastBomImport());
            // todo: add some more assertions
        }
    }
}
