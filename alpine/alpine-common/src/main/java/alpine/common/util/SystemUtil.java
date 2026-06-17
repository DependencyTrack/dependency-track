/*
 * This file is part of Alpine.
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
package alpine.common.util;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This class contains a collection of commonly used static methods which
 * reveal system-wide information. These provide no security-related fixes
 * to any issue, and are merely available as a convenience.
 *
 * @author Steve Springett
 * @since 1.0
 */
@SuppressWarnings("unused")
public final class SystemUtil {

    private static final Runtime.Version JAVA_VERSION = Runtime.version();
    private static final Logger LOGGER = LoggerFactory.getLogger(SystemUtil.class);

    /**
     * Private constructor
     */
    private SystemUtil() {
    }

    /**
     * Return the name of the host operating system.
     * @return String containing the name of the host operating system
     * @since 1.0
     */
    public static String getOsName() {
        return System.getProperty("os.name");
    }

    /**
     * Return the OS architecture.
     * @return String containing the OS architecture
     * @since 1.0
     */
    public static String getOsArchitecture() {
        return System.getProperty("os.arch");
    }

    /**
     * Return the OS version.
     * @return String containing the OS version
     * @since 1.0
     */
    public static String getOsVersion() {
        return System.getProperty("os.version");
    }

    /**
     * Return the username that is executing the current running Java process.
     * @return String containing the username that is executing the current running Java process
     * @since 1.0
     */
    public static String getUserName() {
        return System.getProperty("user.name");
    }

    /**
     * Return the home directory of the user executing the current running Java process.
     * @return String containing the home directory of the user executing the current running Java process
     * @since 1.0
     */
    public static String getUserHome() {
        return System.getProperty("user.home");
    }

    /**
     * Return the Java vendor.
     * @return String containing the Java vendor
     * @since 1.0
     */
    public static String getJavaVendor() {
        return System.getProperty("java.vendor");
    }

    /**
     * Return the Java version.
     * @return JavaVersion containing Java version information
     * @since 1.0
     */
    public static Runtime.Version getJavaVersion() {
        return JAVA_VERSION;
    }

    /**
     * Return the JAVA_HOME environment variable.
     * @return String containing the JAVA_HOME environment variable
     * @since 1.0
     */
    public static String getJavaHome() {
        return System.getProperty("java.home");
    }

    /**
     * Return the temporary directory to be used by Java.
     * @return String containing the temporary directory to be used by Java
     * @since 1.0
     */
    public static String getJavaTempDir() {
        return System.getProperty("java.io.tmpdir");
    }

    /**
     * Returns the number of processor cores available to the JVM.
     * @return an integer of the number of processor core
     * @since 1.0.0
     */
    public static int getCpuCores() {
        return Runtime.getRuntime().availableProcessors();
    }

    /**
     * Returns the number of processor cores available to the JVM.
     * @return an integer of the number of processor core
     * @since 1.9.0
     */
    public static long getMaxMemory() {
        return Runtime.getRuntime().maxMemory();
    }

}
