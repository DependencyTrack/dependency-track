/*
 * This file is part of Dependency-Track.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Copyright (c) Steve Springett. All Rights Reserved.
 */
package org.dependencytrack.event;

import org.junit.Assert;
import org.junit.Test;
import org.owasp.dependencycheck.utils.FileUtils;
import java.io.File;
import java.util.UUID;

public class ScanUploadEventTest {

    @Test
    public void testByteArrayConstructor() {
        UUID uuid = UUID.randomUUID();
        byte[] bom = "testing".getBytes();
        ScanUploadEvent event = new ScanUploadEvent(uuid, bom);
        Assert.assertEquals(uuid, event.getProjectUuid());
        Assert.assertEquals(bom, event.getScan());
        Assert.assertNull(event.getFile());
    }

    @Test
    public void testFileConstructor() {
        UUID uuid = UUID.randomUUID();
        File bitBucket = new File(FileUtils.getBitBucket());
        ScanUploadEvent event = new ScanUploadEvent(uuid, bitBucket);
        Assert.assertEquals(uuid, event.getProjectUuid());
        Assert.assertEquals(bitBucket, event.getFile());
        Assert.assertNull(event.getScan());
    }
}
