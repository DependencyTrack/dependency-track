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

import java.util.ArrayList;
import java.util.List;

class LicenseGroupTest {

    @Test
    void testId() {
        LicenseGroup lg = new LicenseGroup();
        lg.setId(111L);
        Assertions.assertEquals(111L, lg.getId());
    }

    @Test
    void testName() {
        LicenseGroup lg = new LicenseGroup();
        lg.setName("Copyleft");
        Assertions.assertEquals("Copyleft", lg.getName());
    }

    @Test
    void testLicenses() {
        List<License> licenses = new ArrayList<>();
        License license = new License();
        licenses.add(license);
        LicenseGroup lg = new LicenseGroup();
        lg.setLicenses(licenses);
        Assertions.assertEquals(1, lg.getLicenses().size());
        Assertions.assertEquals(license, lg.getLicenses().get(0));
    }

    @Test
    void testRiskWeight() {
        LicenseGroup lg = new LicenseGroup();
        lg.setRiskWeight(9);
        Assertions.assertEquals(9, lg.getRiskWeight());
    }
}
