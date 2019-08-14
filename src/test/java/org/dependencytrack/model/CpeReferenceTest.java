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

public class CpeReferenceTest {

    @Test
    public void testId() {
        CpeReference ref = new CpeReference();
        ref.setId(111L);
        Assert.assertEquals(111L, ref.getId());
    }

    @Test
    public void testCpe() {
        Cpe cpe = new Cpe();
        CpeReference ref = new CpeReference();
        ref.setCpe(cpe);
        Assert.assertEquals(cpe, ref.getCpe());
    }

    @Test
    public void testName() {
        CpeReference ref = new CpeReference();
        ref.setName("CPE Reference Name");
        Assert.assertEquals("CPE Reference Name", ref.getName());
    }

    @Test
    public void testHref() {
        CpeReference ref = new CpeReference();
        ref.setHref("https://example.com");
        Assert.assertEquals("https://example.com", ref.getHref());
    }
}
