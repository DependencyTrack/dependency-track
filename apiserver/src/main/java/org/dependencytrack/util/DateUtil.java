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

import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.TimeZone;

public final class DateUtil {

    private DateUtil() {
    }

    /**
     * Convenience method that parses a date in yyyyMMdd format as UTC midnight
     * and returns a Date object. If the parsing fails, null is returned.
     * @param yyyyMMdd the date string to parse
     * @return a Date object
     * @since 3.0.0
     */
    public static Date parseShortDate(final String yyyyMMdd) {
        final SimpleDateFormat format = new SimpleDateFormat("yyyyMMdd");
        format.setTimeZone(TimeZone.getTimeZone("UTC"));
        try {
            return format.parse(yyyyMMdd);
        } catch (ParseException e) {
            return null;
        }
    }

    /**
     * Formats a Date object into ISO 8601 format.
     * @param date the Date object to convert
     * @return a String representation of an ISO 8601 date
     * @since 3.4.0
     */
    public static String toISO8601(final Date date) {
        final TimeZone tz = TimeZone.getTimeZone("UTC");
        final DateFormat df = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'"); // Quoted "Z" to indicate UTC, no timezone offset
        df.setTimeZone(tz);
        return df.format(date);
    }

    public static Date fromISO8601(final String dateString) {
        if (dateString == null) {
            return null;
        }
        return jakarta.xml.bind.DatatypeConverter.parseDateTime(dateString).getTime();
    }
}
