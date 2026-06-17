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
 * Copyright (c) OWASP Foundation. All Rights Reserved.
 */
package alpine.common.util;

import java.util.UUID;

import org.dependencytrack.search.document.SearchDocument;

/**
 * A collection of useful UUID utilities.
 *
 * @author Steve Springett
 * @since 1.0.0
 */
@SuppressWarnings("unused")
public final class UuidUtil {

    /**
     * Private constructor
     */
    private UuidUtil() { }

    /**
     * Determines if the specified string is a valid UUID.
     * @param uuid the UUID to evaluate
     * @return true if UUID is valid, false if invalid
     * @since 1.0.0
     */
    public static boolean isValidUUID(String uuid) {
        if (uuid == null) {
            return false;
        }

        try {
            UUID.fromString(uuid);
            return true;
        } catch (IllegalArgumentException _) {
            return false;
        }
    }

}
