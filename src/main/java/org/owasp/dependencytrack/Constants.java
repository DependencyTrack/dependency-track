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
 *
 * Copyright (c) Axway. All Rights Reserved.
 */
package org.owasp.dependencytrack;

import org.apache.commons.lang.StringUtils;

import java.io.File;

/**
 * A class containing constants used throughout the application.
 *
 * @author Steve Springett (steve.springett@owasp.org)
 */
public final class Constants {

    /**
     * Private constructor
     */
    private Constants() { }

    /**
     * Specify the Dependency-Track application directory.
     */
    public static final String APP_DIR = getAppHome();

    /**
     * Specify the data directory used by Dependency-Check.
     */
    public static final String DATA_DIR = APP_DIR + File.separator + "data";

    /**
     * Specify the zip archive of the data directory.
     */
    public static final String DATA_FILENAME = "data.zip";

    /**
     * Specify the zip archive of the data directory.
     */
    public static final String DATA_ZIP = APP_DIR + File.separator + DATA_FILENAME;

    /**
     * Specify the global suppression file.
     */
    public static final String SUPPRESSION_FILENAME = "suppressions.xml";

    /**
     * Specify the path and filename to the global suppression file.
     */
    public static final String SUPPRESSION_PATH_FILENAME = DATA_DIR + File.separator + SUPPRESSION_FILENAME;

    /**
     * Specify the NIST data directory used by Dependency-Check.
     */
    public static final String NIST_DIR = APP_DIR + File.separator + "nist";

    /**
     * Specify the directory where logs are stored.
     */
    public static final String LOG_DIR = APP_DIR + File.separator + "log";

    /**
     * Returns the application home directory. This is a configurable option.
     * @return the application home directory
     */
    private static String getAppHome() {
        final String appHome = Config.getInstance().getAppHome();
        if (StringUtils.isNotBlank(appHome)) {
            return appHome;
        }
        return System.getProperty("user.home") + File.separator + "dependency-track";
    }
}
