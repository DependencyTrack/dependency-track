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
package org.dependencytrack.search.document;

import org.dependencytrack.model.Cpe;

import java.util.UUID;

/**
 * A {@link SearchDocument} for {@link Cpe}s.
 *
 * @param id      ID of the {@link Cpe}
 * @param uuid    {@link UUID} of the {@link Cpe}
 * @param cpe22   CPE 2.2 URI of the {@link Cpe}
 * @param cpe23   CPE 2.3 formatted string of the {@link Cpe}
 * @param vendor  Vendor attribute of the {@link Cpe}
 * @param product Product attribute of the {@link Cpe}
 * @param version Version attribute of the {@link Cpe}
 * @since 4.10.0
 */
public record CpeDocument(Long id, UUID uuid, String cpe22, String cpe23, String vendor,
                          String product, String version) implements SearchDocument {

    public CpeDocument(final Cpe cpe) {
        this(cpe.getId(), cpe.getUuid(), cpe.getCpe22(), cpe.getCpe23(), cpe.getVendor(),
                cpe.getProduct(), cpe.getVersion());
    }

}
