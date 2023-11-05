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
package org.dependencytrack.tasks;

import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.event.NistMirrorEvent;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;

import static org.dependencytrack.model.ConfigPropertyConstants.VULNERABILITY_SOURCE_NVD_API_ENABLED;
import static org.dependencytrack.model.ConfigPropertyConstants.VULNERABILITY_SOURCE_NVD_API_URL;

public class NistApiMirrorTaskTest extends PersistenceCapableTest {

    @Before
    public void setUp() {
        qm.createConfigProperty(
                VULNERABILITY_SOURCE_NVD_API_ENABLED.getGroupName(),
                VULNERABILITY_SOURCE_NVD_API_ENABLED.getPropertyName(),
                "true",
                VULNERABILITY_SOURCE_NVD_API_ENABLED.getPropertyType(),
                VULNERABILITY_SOURCE_NVD_API_ENABLED.getDescription()
        );
        qm.createConfigProperty(
                VULNERABILITY_SOURCE_NVD_API_URL.getGroupName(),
                VULNERABILITY_SOURCE_NVD_API_URL.getPropertyName(),
                VULNERABILITY_SOURCE_NVD_API_URL.getDefaultPropertyValue(),
                VULNERABILITY_SOURCE_NVD_API_URL.getPropertyType(),
                VULNERABILITY_SOURCE_NVD_API_URL.getDescription()
        );
    }

    @Test
    @Ignore // For manual testing only
    public void test() {
        new NistApiMirrorTask().inform(new NistMirrorEvent());
    }

}