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
package org.owasp.dependencytrack.model;

import alpine.Config;
import org.owasp.dependencycheck.utils.Settings;
import javax.inject.Singleton;
import java.io.Serializable;

/**
 * This class provides basic information about the application.
 *
 * @author Steve Springett
 * @since 3.0.0
 */
@Singleton
public class About implements Serializable {

    private static final long serialVersionUID = -7573425245706188307L;

    private static final String APPLICATION = Config.getInstance().getApplicationName();
    private static final String VERSION = Config.getInstance().getApplicationVersion();
    private static final String TIMESTAMP = Config.getInstance().getApplicationBuildTimestamp();
    private static String DC_APPLICATION;
    private static String DC_VERSION;

    static {
        Settings settings = new Settings();
        DC_APPLICATION = settings.getString(Settings.KEYS.APPLICATION_NAME);
        DC_VERSION = settings.getString(Settings.KEYS.APPLICATION_VERSION);
    }


    public String getApplication() {
        return APPLICATION;
    }

    public String getVersion() {
        return VERSION;
    }

    public String getTimestamp() {
        return TIMESTAMP;
    }

    public DependencyCheck getDependencyCheck() {
        return new DependencyCheck();
    }

    private static class DependencyCheck {

        public String getApplication() {
            return DC_APPLICATION;
        }

        public String getVersion() {
            return DC_VERSION;
        }
    }

}
