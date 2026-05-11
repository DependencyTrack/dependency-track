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
package org.dependencytrack.persistence.jdbi;

import org.dependencytrack.common.pagination.PageTokenEncoder;
import org.jdbi.v3.core.config.JdbiConfig;

import static java.util.Objects.requireNonNull;

/**
 * @since 5.0.0
 */
public final class PaginationConfig implements JdbiConfig<PaginationConfig> {

    private PageTokenEncoder pageTokenEncoder;

    PaginationConfig(PageTokenEncoder pageTokenEncoder) {
        this.pageTokenEncoder = requireNonNull(pageTokenEncoder, "pageTokenEncoder must not be null");
    }

    @SuppressWarnings("unused") // Used by JDBI to instantiate the class via reflection.
    public PaginationConfig() {
    }

    @Override
    public PaginationConfig createCopy() {
        return new PaginationConfig(pageTokenEncoder);
    }

    void setPageTokenEncoder(PageTokenEncoder pageTokenEncoder) {
        this.pageTokenEncoder = pageTokenEncoder;
    }

    public PageTokenEncoder getPageTokenEncoder() {
        return pageTokenEncoder;
    }

}
