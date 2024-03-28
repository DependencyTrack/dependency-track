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
package org.dependencytrack.parser.common.resolver;

import org.junit.Assert;
import org.junit.Test;

public class CveResolverTest {

    @Test
    public void testPositiveResolutionByFullCveId() {
        String cve_id = CveResolver.getInstance().getValidCveId("CVE-2020-1234");
        Assert.assertNotNull(cve_id);
        Assert.assertEquals("CVE-2020-1234", cve_id);
    }

    @Test
    public void testPositiveResolutionByPartialCveId() {
        String cve_id = CveResolver.getInstance().getValidCveId("2020-1234");
        Assert.assertNotNull(cve_id);
        Assert.assertEquals("CVE-2020-1234", cve_id);
    }
    @Test
    public void testNegativeResolutionByInvalidCveId() {
        String cve_id = CveResolver.getInstance().getValidCveId("20-1234");
        Assert.assertNull(cve_id);
        Assert.assertNotEquals("CVE-2020-1234", cve_id);
    }

    @Test
    public void testNegativeResolutionByInvalidCweId() {
        String cve_id = CveResolver.getInstance().getValidCveId("CVE-12345678");
        Assert.assertNull(cve_id);
        Assert.assertNotEquals("CVE-1234-5678", cve_id);
    }
}
