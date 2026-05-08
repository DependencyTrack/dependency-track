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
package org.dependencytrack.pkgmetadata.resolution.api;

import java.util.regex.Pattern;

/**
 * @since 5.0.0
 */
public enum HashAlgorithm {

    MD5(Pattern.compile("[0-9a-f]{32}", Pattern.CASE_INSENSITIVE)),
    SHA1(Pattern.compile("[0-9a-f]{40}", Pattern.CASE_INSENSITIVE)),
    SHA256(Pattern.compile("[0-9a-f]{64}", Pattern.CASE_INSENSITIVE)),
    SHA512(Pattern.compile("[0-9a-f]{128}", Pattern.CASE_INSENSITIVE));

    private final Pattern pattern;

    HashAlgorithm(Pattern pattern) {
        this.pattern = pattern;
    }

    public boolean isValid(String value) {
        return pattern.matcher(value).matches();
    }

}
