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

import org.dependencytrack.model.Component;
import org.junit.Assert;
import org.junit.Test;
import java.util.LinkedList;
import java.util.List;
import java.util.Optional;

public class RepositoryMetaEventTest {

    @Test
    public void testDefaultConstructor() {
        RepositoryMetaEvent event = new RepositoryMetaEvent();
        Assert.assertEquals(Optional.empty(), event.getComponents());
    }

    @Test
    public void testComponentConstructor() {
        List<Component> components = new LinkedList<>();
        Component component = new Component();
        components.add(component);
        RepositoryMetaEvent event = new RepositoryMetaEvent(components);
        Assert.assertEquals(components, event.getComponents().get());
    }
}
