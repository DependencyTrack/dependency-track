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
package org.dependencytrack.persistence.converter;

import com.fasterxml.jackson.core.type.TypeReference;
import org.dependencytrack.model.OrganizationalContact;

import java.util.List;

/**
 * @since 4.10.0
 */
public class OrganizationalContactsJsonConverter extends AbstractJsonConverter<List<OrganizationalContact>> {

    public OrganizationalContactsJsonConverter() {
        super(new TypeReference<>() {});
    }

    @Override
    public String convertToDatastore(final List<OrganizationalContact> attributeValue) {
        // Overriding is required for DataNucleus to correctly detect the return type.
        return super.convertToDatastore(attributeValue);
    }

    @Override
    public List<OrganizationalContact> convertToAttribute(final String datastoreValue) {
        // Overriding is required for DataNucleus to correctly detect the return type.
        return super.convertToAttribute(datastoreValue);
    }

}
