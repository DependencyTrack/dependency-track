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

import java.time.Instant;
import java.util.Date;

import org.junit.Assert;
import org.junit.Test;

public class ScheduledUtilTest {
   
    @Test
    public void getValueOrEmptyIfNullTest() {
        Integer object = Integer.valueOf(123);
        Assert.assertEquals("123", ScheduledUtil.getValueOrEmptyIfNull(object));
    }

    @Test
    public void getValueOrEmptyIfNullWithNullTest() {
        Integer object = null;
        Assert.assertEquals("", ScheduledUtil.getValueOrEmptyIfNull(object));
    }

    @Test
    public void getDateOrUnknownIfNull() {
        Date date = Date.from(Instant.now());
        Assert.assertEquals(DateUtil.toISO8601(date), ScheduledUtil.getDateOrUnknownIfNull(date));
    }

    @Test
    public void getDateOrUnknownIfNullWithNull() {
        Date date = null;
        Assert.assertEquals("Unknown", ScheduledUtil.getDateOrUnknownIfNull(date));
    }
}
