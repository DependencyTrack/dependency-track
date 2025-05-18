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
package org.dependencytrack.event;

import org.dependencytrack.resources.v1.vo.CloneProjectRequest;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.UUID;

class CloneProjectEventTest {

    @Test
    void testEvent() {
        UUID uuid = UUID.randomUUID();
        CloneProjectRequest request = new CloneProjectRequest(uuid.toString(), "1.0", true,
                true, true, true, true, true,
                true, true, false);
        CloneProjectEvent event = new CloneProjectEvent(request);
        Assertions.assertEquals(request, event.getRequest());
    }
}
