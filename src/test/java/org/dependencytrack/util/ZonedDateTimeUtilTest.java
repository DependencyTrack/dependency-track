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


package org.dependencytrack.util;

import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;

import org.junit.Assert;
import org.junit.Test;

public class ZonedDateTimeUtilTest {
    
    @Test
    public void toISO8601Test() {
        final ZonedDateTime testTime = ZonedDateTime.parse("2024-05-31T13:24:46Z", DateTimeFormatter.ISO_OFFSET_DATE_TIME);
        Assert.assertEquals("2024-05-31T13:24:46Z", ZonedDateTimeUtil.toISO8601(testTime));
    }

    @Test
    public void fromISO8601Test() {
        final ZonedDateTime testTime = ZonedDateTime.parse("2024-05-31T13:24:46Z", DateTimeFormatter.ISO_OFFSET_DATE_TIME);
        Assert.assertEquals(testTime, ZonedDateTimeUtil.fromISO8601("2024-05-31T13:24:46Z"));
    }

    @Test
    public void fromISO8601WithNullTest() {
        final ZonedDateTime testTime = null;
        Assert.assertEquals(testTime, ZonedDateTimeUtil.fromISO8601(null));
    }
}
