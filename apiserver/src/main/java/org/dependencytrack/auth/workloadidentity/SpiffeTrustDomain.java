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
 * Copyright (c) OWASP Foundation. All Rights Reserved.
 */
package org.dependencytrack.auth.workloadidentity;

import java.util.Locale;
import java.util.regex.Pattern;

/// @since 5.2.0
public final class SpiffeTrustDomain {

    private static final Pattern PATTERN = Pattern.compile("^[a-zA-Z0-9._-]+$");

    private SpiffeTrustDomain() {}

    public static boolean isValid(String trustDomain) {
        return PATTERN.matcher(trustDomain).matches();
    }

    public static String idPrefix(String trustDomain) {
        return "spiffe://%s/".formatted(trustDomain.toLowerCase(Locale.ROOT));
    }

    public static boolean isValidBindingSubject(String trustDomain, String subject) {
        return subject.startsWith(idPrefix(trustDomain)) && (!subject.endsWith("*") || subject.endsWith("/*"));
    }
}
