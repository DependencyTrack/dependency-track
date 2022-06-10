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

import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.event.GoogleOSVMirrorEvent;
import org.dependencytrack.model.ConfigPropertyConstants;
import org.dependencytrack.tasks.OSVDownloadTask;
import org.junit.Test;

public class OSVDownloadTaskTest extends PersistenceCapableTest {

    @Test
    public void informTest() {
        final var task = new OSVDownloadTask();
        final var event = new GoogleOSVMirrorEvent();
        final var acceptArtifactProp = ConfigPropertyConstants.VULNERABILITY_SOURCE_GOOGLE_OSV_ENABLED;
        qm.createConfigProperty(acceptArtifactProp.getGroupName(), acceptArtifactProp.getPropertyName(), "true", acceptArtifactProp.getPropertyType(), acceptArtifactProp.getDescription());

        // TODO : add assertions on QueryManager database
        // Commenting task below to avoid database write
        // task.inform(event);
    }
}