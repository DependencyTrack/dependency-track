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
package org.dependencytrack.model;
import org.cyclonedx.model.Component;
/**
 * Enum class for tracking individual components scope.
 * Scope would be deriving from different SBOM provider.
 * * <a href="https://cyclonedx.org/docs/1.6/json/#components_items_scope">Cyclondx Reference</a>
 * * @author Anant Kurapati
 * @since 4.14.0
 */
public enum Scope {
    REQUIRED("Required"),
    OPTIONAL("Optional"),
    EXCLUDED("Excluded");

    private final String label;

    Scope(String label) {
        this.label = label;
    }

    public String getLabel() {
        return label;
    }
    public static Scope getMappedScope(Component.Scope scope) {
        return switch (scope){
            case REQUIRED ->  Scope.REQUIRED;
            case EXCLUDED ->  Scope.EXCLUDED;
            case OPTIONAL -> Scope.OPTIONAL;
        };
    }
}
