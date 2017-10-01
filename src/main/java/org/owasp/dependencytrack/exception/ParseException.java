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
package org.owasp.dependencytrack.exception;

/**
 * Exception for when parsing files.
 *
 * @author Steve Springett
 * @since 3.0.0
 */
public class ParseException extends Exception {

    /**
     * @since 3.0.0
     */
    public ParseException(String message) {
        super(message);
    }

    /**
     * @since 3.0.0
     */
    public ParseException(Throwable cause) {
        super(cause);
    }

    /**
     * @since 3.0.0
     */
    public ParseException(String message, Throwable cause) {
        super(message, cause);
    }
}
