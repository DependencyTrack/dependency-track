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
package org.dependencytrack.model;

import org.junit.Assert;
import org.junit.Test;

public class ClassifierTest {

    @Test
    public void testEnums() {
        Assert.assertEquals("APPLICATION", Classifier.APPLICATION.name());
        Assert.assertEquals("FRAMEWORK", Classifier.FRAMEWORK.name());
        Assert.assertEquals("LIBRARY", Classifier.LIBRARY.name());
        Assert.assertEquals("CONTAINER", Classifier.CONTAINER.name());
        Assert.assertEquals("OPERATING_SYSTEM", Classifier.OPERATING_SYSTEM.name());
        Assert.assertEquals("DEVICE", Classifier.DEVICE.name());
        Assert.assertEquals("FIRMWARE", Classifier.FIRMWARE.name());
        Assert.assertEquals("FILE", Classifier.FILE.name());
    }
}
