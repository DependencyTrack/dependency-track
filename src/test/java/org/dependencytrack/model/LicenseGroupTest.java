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
import java.util.ArrayList;
import java.util.List;

public class LicenseGroupTest {

    @Test
    public void testId() {
        LicenseGroup lg = new LicenseGroup();
        lg.setId(111L);
        Assert.assertEquals(111L, lg.getId());
    }

    @Test
    public void testName() {
        LicenseGroup lg = new LicenseGroup();
        lg.setName("Copyleft");
        Assert.assertEquals("Copyleft", lg.getName());
    }

    @Test
    public void testLicenses() {
        List<License> licenses = new ArrayList<>();
        License license = new License();
        licenses.add(license);
        LicenseGroup lg = new LicenseGroup();
        lg.setLicenses(licenses);
        Assert.assertEquals(1, lg.getLicenses().size());
        Assert.assertEquals(license, lg.getLicenses().get(0));
    }

    @Test
    public void testRiskWeight() {
        LicenseGroup lg = new LicenseGroup();
        lg.setRiskWeight(9);
        Assert.assertEquals(9, lg.getRiskWeight());
    }
}
