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

public class VulnerableSoftwareTest {

    @Test
    public void testId() {
        VulnerableSoftware vs = new VulnerableSoftware();
        vs.setId(111L);
        Assert.assertEquals(111L, vs.getId());
    }

    @Test
    public void testCpe22() {
        VulnerableSoftware vs = new VulnerableSoftware();
        vs.setCpe22("cpe:/a:gimp:gimp:2.10.0");
        Assert.assertEquals("cpe:/a:gimp:gimp:2.10.0", vs.getCpe22());
    }

    @Test
    public void testCpe23() {
        VulnerableSoftware vs = new VulnerableSoftware();
        vs.setCpe23("cpe:2.3:a:gimp:gimp:2.10.0:*:*:*:*:*:*:*");
        Assert.assertEquals("cpe:2.3:a:gimp:gimp:2.10.0:*:*:*:*:*:*:*", vs.getCpe23());
    }

    @Test
    public void testVulnerableSoftwareFields() {
        VulnerableSoftware vs = new VulnerableSoftware();
        vs.setPart("a");
        vs.setVendor("acme");
        vs.setProduct("cool-product");
        vs.setVersion("1.1.0");
        vs.setUpdate("*");
        vs.setEdition("*");
        vs.setLanguage("*");
        vs.setSwEdition("*");
        vs.setTargetSw("*");
        vs.setTargetHw("*");
        vs.setOther("*");
        vs.setVersionEndExcluding("111");
        vs.setVersionEndIncluding("222");
        vs.setVersionStartExcluding("333");
        vs.setVersionStartIncluding("444");
        vs.setVulnerable(true);
        Assert.assertEquals("a", vs.getPart());
        Assert.assertEquals("acme", vs.getVendor());
        Assert.assertEquals("cool-product", vs.getProduct());
        Assert.assertEquals("1.1.0", vs.getVersion());
        Assert.assertEquals("*", vs.getUpdate());
        Assert.assertEquals("*", vs.getEdition());
        Assert.assertEquals("*", vs.getLanguage());
        Assert.assertEquals("*", vs.getSwEdition());
        Assert.assertEquals("*", vs.getTargetSw());
        Assert.assertEquals("*", vs.getTargetHw());
        Assert.assertEquals("*", vs.getOther());
        Assert.assertEquals("111", vs.getVersionEndExcluding());
        Assert.assertEquals("222", vs.getVersionEndIncluding());
        Assert.assertEquals("333", vs.getVersionStartExcluding());
        Assert.assertEquals("444", vs.getVersionStartIncluding());
        Assert.assertTrue(vs.isVulnerable());
    }

    @Test
    public void testUuid() {
        UUID uuid = UUID.randomUUID();
        VulnerableSoftware vs = new VulnerableSoftware();
        vs.setUuid(uuid);
        Assert.assertEquals(uuid.toString(), vs.getUuid().toString());
    }
}
