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
package org.dependencytrack.dex.engine.persistence.jdbi;

import org.dependencytrack.common.pagination.PageTokenEncoder;
import org.jdbi.v3.core.config.JdbiConfig;
import org.jspecify.annotations.Nullable;

public final class PaginationConfig implements JdbiConfig<PaginationConfig> {

    private @Nullable PageTokenEncoder pageTokenEncoder;

    @SuppressWarnings("unused") // Used by JDBI.
    public PaginationConfig() {
    }

    private PaginationConfig(@Nullable PageTokenEncoder pageTokenEncoder) {
        this.pageTokenEncoder = pageTokenEncoder;
    }

    @Override
    public PaginationConfig createCopy() {
        return new PaginationConfig(pageTokenEncoder);
    }

    public @Nullable PageTokenEncoder getPageTokenEncoder() {
        return pageTokenEncoder;
    }

    void setPageTokenEncoder(PageTokenEncoder pageTokenEncoder) {
        this.pageTokenEncoder = pageTokenEncoder;
    }

}
