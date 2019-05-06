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
package org.dependencytrack.util;

import org.junit.Assert;
import org.junit.Test;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.Month;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.Date;

public class DateUtilTest {

    @Test
    public void testParseShortDate() throws Exception {
        Date date = DateUtil.parseShortDate("20191231");
        LocalDate localDate = date.toInstant().atZone(ZoneId.systemDefault()).toLocalDate();
        Assert.assertEquals(Month.DECEMBER, localDate.getMonth());
        Assert.assertEquals(31, localDate.getDayOfMonth());
        Assert.assertEquals(2019, localDate.getYear());
    }

    @Test
    public void testParseDate() throws Exception {
        Date date = DateUtil.parseDate("20191231153012");
        LocalDateTime localDateTime = date.toInstant().atZone(ZoneId.systemDefault()).toLocalDateTime();
        Assert.assertEquals(Month.DECEMBER, localDateTime.getMonth());
        Assert.assertEquals(31, localDateTime.getDayOfMonth());
        Assert.assertEquals(2019, localDateTime.getYear());
        Assert.assertEquals(15, localDateTime.getHour());
        Assert.assertEquals(30, localDateTime.getMinute());
        Assert.assertEquals(12, localDateTime.getSecond());
    }

    @Test
    public void testDiff() {
        LocalDate d1 =  LocalDate.of(2019, Month.JANUARY, 1);
        LocalDate d2 =  LocalDate.of(2017, Month.JANUARY, 1);
        long diff = DateUtil.diff(java.sql.Date.valueOf(d2), java.sql.Date.valueOf(d1));
        Assert.assertEquals(730, diff);
    }

    @Test
    public void testToISO8601() {
        Date date = Date.from(LocalDateTime.of(2019, Month.JANUARY, 31, 15, 30, 12).toInstant(ZoneOffset.UTC));
        String iso8601Date = DateUtil.toISO8601(date);
        Assert.assertEquals("2019-01-31T15:30:12Z", iso8601Date);
    }
}
