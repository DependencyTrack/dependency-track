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
package org.owasp.dependencytrack;

import org.owasp.dependencycheck.utils.Settings;
import org.owasp.dependencytrack.logging.Logger;
import java.io.IOException;
import java.util.Properties;

/**
 * The Config class is responsible for reading the application.properties file
 */
public final class Config {

    private static final Logger logger = Logger.getLogger(Config.class);
    private static final String propFile = "application.properties";
    private static Config instance;
    private static Properties properties;
    private static Settings settings;


    /**
     * Returns an instance of the Config object
     * @return a Config object
     */
    public static Config getInstance() {
        if (instance == null) {
            instance = new Config();
        }
        if (properties == null) {
            instance.init();
        }
        if (settings == null) {
            Settings.initialize();
        }
        return instance;
    }

    /**
     * Initialize the Config object. This method should only be called once.
     */
    private void init() {
        if (properties != null) {
            return;
        }

        logger.info("Initializing Configuration");
        properties = new Properties();
        try {
            properties.load(this.getClass().getClassLoader().getResourceAsStream("application.properties"));
        } catch (IOException e) {
            logger.error("Unable to load " + propFile);
        }
    }

    /**
     * Return the configured value for the specified ConfigItem
     * @param item The ConfigItem to return the configuration for
     * @return a String of the value of the configuration
     */
    public String getProperty(ConfigItem item) {
        return properties.getProperty(item.propertyName);
    }

    public int getPropertyAsInt(ConfigItem item) {
        try {
            return Integer.parseInt(getProperty(item));
        } catch (NumberFormatException e) {
            logger.error("Error parsing number from property: " + item.name());
            throw e;
        }
    }

    public long getPropertyAsLong(ConfigItem item) {
        try {
            return Long.parseLong(getProperty(item));
        } catch (NumberFormatException e) {
            logger.error("Error parsing number from property: " + item.name());
            throw e;
        }
    }

    public boolean getPropertyAsBoolean(ConfigItem item) {
        return "true".equalsIgnoreCase(getProperty(item));
    }

    public String getProperty(String key) {
        return properties.getProperty(key);
    }

    public static boolean isUnitTestsEnabled() {
        return Boolean.valueOf(System.getProperty("dependency-track.unittests.enabled", "false"));
    }

    public static void enableUnitTests() {
        System.setProperty("dependency-track.unittests.enabled", "true");
    }

}