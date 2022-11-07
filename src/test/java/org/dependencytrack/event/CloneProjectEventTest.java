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
package org.dependencytrack.event;

import org.dependencytrack.resources.v1.vo.CloneProjectRequest;
import org.junit.Assert;
import org.junit.Test;

import java.util.UUID;

public class CloneProjectEventTest {

    @Test
    public void testEvent() {
        UUID uuid = UUID.randomUUID();
        CloneProjectRequest request = new CloneProjectRequest(uuid.toString(), "1.0", true, true, true, true, true, true, true);
        CloneProjectEvent event = new CloneProjectEvent(request);
        Assert.assertEquals(request, event.getRequest());
    }
}
