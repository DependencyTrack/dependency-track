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
import java.util.UUID;

public class CpeTest {

    @Test
    public void testId() {
        Cpe cpe = new Cpe();
        cpe.setId(111L);
        Assert.assertEquals(111L, cpe.getId());
    }

    @Test
    public void testCpe22() {
        Cpe cpe = new Cpe();
        cpe.setCpe22("cpe:/a:gimp:gimp:2.10.0");
        Assert.assertEquals("cpe:/a:gimp:gimp:2.10.0", cpe.getCpe22());
    }

    @Test
    public void testCpe23() {
        Cpe cpe = new Cpe();
        cpe.setCpe23("cpe:2.3:a:gimp:gimp:2.10.0:*:*:*:*:*:*:*");
        Assert.assertEquals("cpe:2.3:a:gimp:gimp:2.10.0:*:*:*:*:*:*:*", cpe.getCpe23());
    }

    @Test
    public void testTitle() {
        Cpe cpe = new Cpe();
        cpe.setTitle("Gimp v2.10.0");
        Assert.assertEquals("Gimp v2.10.0", cpe.getTitle());
    }

    @Test
    public void testCpeFields() {
        Cpe cpe = new Cpe();
        cpe.setPart("a");
        cpe.setVendor("acme");
        cpe.setProduct("cool-product");
        cpe.setVersion("1.1.0");
        cpe.setUpdate("*");
        cpe.setEdition("*");
        cpe.setLanguage("*");
        cpe.setSwEdition("*");
        cpe.setTargetSw("*");
        cpe.setTargetHw("*");
        cpe.setOther("*");
        Assert.assertEquals("a", cpe.getPart());
        Assert.assertEquals("acme", cpe.getVendor());
        Assert.assertEquals("cool-product", cpe.getProduct());
        Assert.assertEquals("1.1.0", cpe.getVersion());
        Assert.assertEquals("*", cpe.getUpdate());
        Assert.assertEquals("*", cpe.getEdition());
        Assert.assertEquals("*", cpe.getLanguage());
        Assert.assertEquals("*", cpe.getSwEdition());
        Assert.assertEquals("*", cpe.getTargetSw());
        Assert.assertEquals("*", cpe.getTargetHw());
        Assert.assertEquals("*", cpe.getOther());
    }

    @Test
    public void testUuid() {
        UUID uuid = UUID.randomUUID();
        Cpe cpe = new Cpe();
        cpe.setUuid(uuid);
        Assert.assertEquals(uuid.toString(), cpe.getUuid().toString());
    }
}
