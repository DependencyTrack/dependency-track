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
package org.dependencytrack.resources.v1.vo;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.ws.rs.BadRequestException;
import org.dependencytrack.resources.v1.problems.ProblemDetails;

import java.util.Arrays;
import java.util.stream.Collectors;

/// @since 5.1.0
@Schema(description = "The counting mode for the `X-Total-Count` response header.")
public enum TotalCountMode {

    EXACT,
    BOUNDED;

    @SuppressWarnings("unused") // Called reflectively by JAX-RS.
    public static TotalCountMode fromString(String value) {
        try {
            return valueOf(value);
        } catch (IllegalArgumentException _) {
            throw new BadRequestException(
                    new ProblemDetails(
                            400,
                            "Invalid query parameter",
                            "\"%s\" is not a valid value for the totalCount parameter. Valid values are: %s.".formatted(
                                    value,
                                    Arrays.stream(values())
                                            .map(Enum::name)
                                            .collect(Collectors.joining(", "))))
                            .toResponse());
        }
    }

}
