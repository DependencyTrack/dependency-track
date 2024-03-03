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

import org.junit.Assert;
import org.junit.Test;

import java.util.UUID;

public class BomUploadEventTest {

    @Test
    public void testByteArrayConstructor() {
        UUID uuid = UUID.randomUUID();
        byte[] bom = "testing".getBytes();
        BomUploadEvent event = new BomUploadEvent(null, bom);
        Assert.assertEquals(uuid, event.getProject().getUuid());
        Assert.assertNotEquals(bom, event.getBom()); // should be a cloned byte array - not the same reference
        Assert.assertTrue(event.getBom().length > 0);
    }

}
