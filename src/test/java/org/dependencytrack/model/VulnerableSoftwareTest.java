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
package org.dependencytrack.model;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.UUID;

class VulnerableSoftwareTest {

    @Test
    void testId() {
        VulnerableSoftware vs = new VulnerableSoftware();
        vs.setId(111L);
        Assertions.assertEquals(111L, vs.getId());
    }

    @Test
    void testCpe22() {
        VulnerableSoftware vs = new VulnerableSoftware();
        vs.setCpe22("cpe:/a:gimp:gimp:2.10.0");
        Assertions.assertEquals("cpe:/a:gimp:gimp:2.10.0", vs.getCpe22());
    }

    @Test
    void testCpe23() {
        VulnerableSoftware vs = new VulnerableSoftware();
        vs.setCpe23("cpe:2.3:a:gimp:gimp:2.10.0:*:*:*:*:*:*:*");
        Assertions.assertEquals("cpe:2.3:a:gimp:gimp:2.10.0:*:*:*:*:*:*:*", vs.getCpe23());
    }

    @Test
    void testVulnerableSoftwareFields() {
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
        Assertions.assertEquals("a", vs.getPart());
        Assertions.assertEquals("acme", vs.getVendor());
        Assertions.assertEquals("cool-product", vs.getProduct());
        Assertions.assertEquals("1.1.0", vs.getVersion());
        Assertions.assertEquals("*", vs.getUpdate());
        Assertions.assertEquals("*", vs.getEdition());
        Assertions.assertEquals("*", vs.getLanguage());
        Assertions.assertEquals("*", vs.getSwEdition());
        Assertions.assertEquals("*", vs.getTargetSw());
        Assertions.assertEquals("*", vs.getTargetHw());
        Assertions.assertEquals("*", vs.getOther());
        Assertions.assertEquals("111", vs.getVersionEndExcluding());
        Assertions.assertEquals("222", vs.getVersionEndIncluding());
        Assertions.assertEquals("333", vs.getVersionStartExcluding());
        Assertions.assertEquals("444", vs.getVersionStartIncluding());
        Assertions.assertTrue(vs.isVulnerable());
    }

    @Test
    void testUuid() {
        UUID uuid = UUID.randomUUID();
        VulnerableSoftware vs = new VulnerableSoftware();
        vs.setUuid(uuid);
        Assertions.assertEquals(uuid.toString(), vs.getUuid().toString());
    }
}
