/*
 * This file is part of Dependency-Track.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Copyright (c) Steve Springett. All Rights Reserved.
 */
package org.owasp.dependencytrack.util;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.concurrent.TimeUnit;

public class DateUtil {

    private DateUtil() { }

    /**
     * Convenience method that parses a date in yyyyMMdd format and
     * returns a Date object. If the parsing fails, null is returned.
     * @param yyyyMMdd the date string to parse
     * @return a Date object
     * @since 3.0.0
     */
    public static Date parseShortDate(String yyyyMMdd) {
        SimpleDateFormat format = new SimpleDateFormat("yyyyMMdd");
        try {
            return format.parse(yyyyMMdd);
        } catch (ParseException e) {
            return null;
        }
    }

    /**
     * Convenience method that returns the difference (in days) between
     * two dates.
     * @param start the first date
     * @param end the second date
     * @return the difference in days
     * @since 3.0.0
     */
    public static long diff(Date start, Date end) {
        long diff = end.getTime() - start.getTime();
        return TimeUnit.DAYS.convert(diff, TimeUnit.MILLISECONDS);
    }

}
