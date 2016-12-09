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

    public enum Key {
        APPLICATION_NAME("application.name"),
        APPLICATION_VERSION("application.version"),
        APPLICATION_TIMESTAMP("application.timestamp"),
        DATABASE_MODE("database.mode"),
        DATABASE_PORT("database.port"),
        ENFORCE_AUTHENTICATION("enforce.authentication"),
        ENFORCE_AUTHORIZATION("enforce.authorization"),
        LDAP_SERVER_URL("ldap.server.url"),
        LDAP_DOMAIN("ldap.domain"),
        HTTP_PROXY_ADDRESS("http.proxy.address"),
        HTTP_PROXY_PORT("http.proxy.port");

        String propertyName;
        private Key(String item) {
            this.propertyName = item;
        }
    }

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
     * Return the configured value for the specified Key
     * @param key The Key to return the configuration for
     * @return a String of the value of the configuration
     */
    public String getProperty(Key key) {
        return properties.getProperty(key.propertyName);
    }

    public int getPropertyAsInt(Key key) {
        try {
            return Integer.parseInt(getProperty(key));
        } catch (NumberFormatException e) {
            logger.error("Error parsing number from property: " + key.name());
            throw e;
        }
    }

    public long getPropertyAsLong(Key key) {
        try {
            return Long.parseLong(getProperty(key));
        } catch (NumberFormatException e) {
            logger.error("Error parsing number from property: " + key.name());
            throw e;
        }
    }

    public boolean getPropertyAsBoolean(Key key) {
        return "true".equalsIgnoreCase(getProperty(key));
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