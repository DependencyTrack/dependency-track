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
package org.dependencytrack.integrations;

import org.dependencytrack.model.Finding;
import org.dependencytrack.model.Project;
import org.junit.Assert;
import org.junit.Test;
import java.io.IOException;
import java.io.InputStream;
import java.util.Collections;
import java.util.List;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class ProjectFindingUploaderTest {

    @Test
    @SuppressWarnings("unchecked")
    public final void projectFindingMethodsTest() throws IOException {
        Project project = new Project();
        List<Finding> findings = Collections.EMPTY_LIST;
        ProjectFindingUploader uploader = mock(ProjectFindingUploader.class);
        when(uploader.process(project, findings)).thenReturn(new InputStream() {
            @Override
            public int read() throws IOException {
                return 1;
            }
            @Override
            public int available() throws IOException {
                return 1;
            }
        });
        InputStream in = uploader.process(project, findings);
        Assert.assertTrue(in != null && in.available() == 1);
        uploader.upload(project, in);
        when(uploader.isProjectConfigured(project)).thenReturn(true);
        Assert.assertTrue(uploader.isProjectConfigured(project));
        when(uploader.isProjectConfigured(project)).thenReturn(false);
        Assert.assertFalse(uploader.isProjectConfigured(project));
    }
}
