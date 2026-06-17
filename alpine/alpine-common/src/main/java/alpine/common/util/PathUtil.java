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

import java.io.File;

/**
 * The utility class for working with various paths.
 *
 * @author Steve Springett
 * @since 1.3.0
 */
public class PathUtil {

    /**
     * Private constructor
     */
    private PathUtil() { }

    /**
     * Resolves relative paths (currently only ~/ home directories).
     * @param path the path to resolve
     * @return the resolved path
     * @since 1.3.0
     */
    public static String resolve(String path) {
        if (path == null) {
            return null;
        }
        if (path.startsWith("~/") || path.startsWith("~\\")) {
            return SystemUtil.getUserHome() + path.substring(1);
        }
        return path;
    }
}
