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
package org.dependencytrack.resources.v2.exception;

import org.dependencytrack.api.v2.model.ProblemDetails;

import jakarta.ws.rs.ClientErrorException;
import jakarta.ws.rs.ext.Provider;
import java.util.Map;

/**
 * @since 5.0.0
 */
@Provider
public final class ClientErrorExceptionMapper extends ProblemDetailsExceptionMapper<ClientErrorException, ProblemDetails> {

    private static final Map<Integer, String> DETAIL_BY_STATUS = Map.ofEntries(
            Map.entry(401, "Not authorized to access the requested resource."),
            Map.entry(403, "Not permitted to access the requested resource."),
            Map.entry(404, "The requested resource could not be found."),
            Map.entry(409, "The resource already exists."));

    @Override
    public ProblemDetails map(final ClientErrorException exception) {
        return ProblemDetails.builder()
                .status(exception.getResponse().getStatus())
                .title(exception.getResponse().getStatusInfo().getReasonPhrase())
                .detail(DETAIL_BY_STATUS.getOrDefault(
                        exception.getResponse().getStatus(),
                        exception.getMessage()))
                .build();
    }

}
