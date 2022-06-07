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
 * Copyright (c) Steve Springett. All Rights Reserved.
 */
package org.dependencytrack.util;

import java.util.Base64;
import java.util.Objects;

import static org.apache.http.HttpHeaders.AUTHORIZATION;

public final class HttpUtil {

    /**
     * Private constructor.
     */
    private HttpUtil() {
    }

    public static String basicAuthHeader(final String username, final String password) {
        return AUTHORIZATION + ": " + basicAuthHeaderValue(username, password);
    }

    public static String basicAuthHeaderValue(final String username, final String password) {
        return "Basic " +
                Base64.getEncoder().encodeToString(
                        String.format("%s:%s", Objects.toString(username, ""), Objects.toString(password, ""))
                                .getBytes()
                );
    }
}
