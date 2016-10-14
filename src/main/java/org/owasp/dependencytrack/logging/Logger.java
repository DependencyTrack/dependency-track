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
package org.owasp.dependencytrack.logging;

/**
 * All logging is handled through this class. This class wraps an actual logging implementation
 * or logging framework so that implementations can be swapped out without having to modify
 * classes that use this logging mechanism.
 */
public final class Logger {

    /**
     * The logging framework being used.
     */
    private org.slf4j.Logger log;

    /**
     * Create an instance of this class and initialize the underlying logging framework.
     * @param clazz The class to use when writing log information
     * @return An instance of the Logger class
     */
    public static Logger getLogger(Class<?> clazz) {
        return new Logger(clazz);
    }

    /**
     * Create an instance of this class and initialize the underlying logging framework.
     * @param clazz The class to use when writing log information
     */
    private Logger(Class<?> clazz) {
        log = org.slf4j.LoggerFactory.getLogger(clazz);
    }

    public boolean isInfoEnabled() {
        return log.isInfoEnabled();
    }

    public boolean isDebugEnabled() {
        return log.isDebugEnabled();
    }

    public boolean isErrorEnabled() {
        return log.isErrorEnabled();
    }

    public boolean isTraceEnabled() {
        return log.isTraceEnabled();
    }

    public boolean isWarnEnabled() {
        return log.isWarnEnabled();
    }

    public void info(String string) {
        log.info(string);
    }

    public void info(String string, Throwable throwable) {
        log.info(string, throwable);
    }

    public void debug(String string) {
        log.debug(string);
    }

    public void debug(String string, Throwable throwable) {
        log.debug(string, throwable);
    }

    public void error(String string) {
        log.error(string);
    }

    public void error(String string, Throwable throwable) {
        log.error(string, throwable);
    }

    public void trace(String string) {
        log.trace(string);
    }

    public void trace(String string, Throwable throwable) {
        log.trace(string, throwable);
    }

    public void warn(String string) {
        log.warn(string);
    }

    public void warn(String string, Throwable throwable) {
        log.warn(string, throwable);
    }

}
