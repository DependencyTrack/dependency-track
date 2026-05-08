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
package org.dependencytrack.plugin.api;

import org.dependencytrack.plugin.api.ExtensionTestCheck.Status;
import org.jspecify.annotations.Nullable;

import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static java.util.Objects.requireNonNull;

/**
 * Result of an extension test.
 * <p>
 * A test result is composed of one or more {@link ExtensionTestCheck}s.
 * Checks must be registered upfront, with their status defaulting to {@link Status#SKIPPED}.
 * Use {@link #pass(String)} or {@link #fail(String, String)} to update the status of registered checks.
 * <p>
 * If at least one check failed, the entire test is considered to have failed.
 *
 * @since 5.0.0
 */
public final class ExtensionTestResult {

    private final Map<String, ExtensionTestCheck> checkByName = new LinkedHashMap<>();

    private ExtensionTestResult(Collection<String> checkNames) {
        requireNonNull(checkNames, "checkNames must not be null");
        if (checkNames.isEmpty()) {
            throw new IllegalArgumentException("checkNames must not be empty");
        }
        for (final var checkName : checkNames) {
            checkByName.put(checkName, new ExtensionTestCheck(checkName, Status.SKIPPED, null));
        }
    }

    public static ExtensionTestResult ofChecks(String... checkNames) {
        return new ExtensionTestResult(List.of(checkNames));
    }

    public ExtensionTestResult pass(String checkName) {
        requireRegistered(checkName);
        checkByName.put(checkName, new ExtensionTestCheck(checkName, Status.PASSED, null));
        return this;
    }

    public ExtensionTestResult fail(String checkName, @Nullable String message) {
        requireRegistered(checkName);
        checkByName.put(checkName, new ExtensionTestCheck(checkName, Status.FAILED, message));
        return this;
    }

    public List<ExtensionTestCheck> checks() {
        return List.copyOf(checkByName.values());
    }

    public boolean isFailed() {
        return checkByName.values().stream()
                .map(ExtensionTestCheck::status)
                .anyMatch(Status.FAILED::equals);
    }

    private void requireRegistered(String checkName) {
        if (!checkByName.containsKey(checkName)) {
            throw new IllegalArgumentException(
                    "No check with name '%s' was registered".formatted(checkName));
        }
    }

}