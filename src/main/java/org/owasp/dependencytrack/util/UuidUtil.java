/*
 * This file is part of Dependency-Track.
 *
 * Dependency-Track is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option) any
 * later version.
 *
 * Dependency-Track is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * Dependency-Track. If not, see http://www.gnu.org/licenses/.
 */
package org.owasp.dependencytrack.util;

import org.apache.commons.lang3.StringUtils;
import java.util.regex.Pattern;

public class UuidUtil {

    private static final Pattern uuidPattern = Pattern.compile("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$");

    private UuidUtil() { }

    public static String insertHyphens(String uuidWithoutHyphens) {
        return uuidWithoutHyphens.replaceFirst( "(\\p{XDigit}{8})(\\p{XDigit}{4})(\\p{XDigit}{4})(\\p{XDigit}{4})(\\p{XDigit}+)", "$1-$2-$3-$4-$5" );
    }

    public static String stripHyphens(String uuid) {
        return uuid.replaceAll("-", "");
    }

    public static boolean isValidUUID(String uuid) {
        return !StringUtils.isEmpty(uuid) && uuidPattern.matcher(uuid).matches();
    }

}
