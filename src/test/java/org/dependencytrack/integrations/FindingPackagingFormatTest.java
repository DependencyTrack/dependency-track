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

import alpine.Config;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.model.Project;
import org.json.JSONObject;
import org.junit.Assert;
import org.junit.Test;
import java.util.Collections;

public class FindingPackagingFormatTest extends PersistenceCapableTest {

    @Test
    @SuppressWarnings("unchecked")
    public void wrapperTest() {
        Project project = qm.createProject(
                "Test", "Sample project", "1.0", null, null, null, true, false);
        FindingPackagingFormat fpf = new FindingPackagingFormat(
                project.getUuid(),
                Collections.EMPTY_LIST
        );
        JSONObject root = fpf.getDocument();

        JSONObject meta = root.getJSONObject("meta");
        Assert.assertEquals(Config.getInstance().getApplicationName(), meta.getString("application"));
        Assert.assertEquals(Config.getInstance().getApplicationVersion(), meta.getString("version"));
        Assert.assertNotNull(meta.getString("timestamp"));

        JSONObject pjson = root.getJSONObject("project");
        Assert.assertEquals(project.getName(), pjson.getString("name"));
        Assert.assertEquals(project.getDescription(), pjson.getString("description"));
        Assert.assertEquals(project.getVersion(), pjson.getString("version"));

        Assert.assertEquals("1.0", root.getString("version"));
    }
}
