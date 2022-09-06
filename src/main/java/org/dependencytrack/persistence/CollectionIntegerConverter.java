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
package org.dependencytrack.persistence;

import alpine.common.logging.Logger;
import org.apache.commons.lang3.StringUtils;

import javax.jdo.AttributeConverter;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;

public class CollectionIntegerConverter implements AttributeConverter<Collection<Integer>, String> {

    private static final Logger LOGGER = Logger.getLogger(CollectionIntegerConverter.class);

    public String convertToDatastore(final Collection<Integer> attribute) {
        if (attribute == null) {
            return null;
        }
        final StringBuilder sb = new StringBuilder();
        final Iterator<Integer> iterator = attribute.iterator();
        while (iterator.hasNext()) {
            sb.append(iterator.next());
            if (iterator.hasNext()) {
                sb.append(",");
            }
        }
        return sb.toString();
    }

    public Collection<Integer> convertToAttribute(final String columnValue) {
        if (columnValue == null || StringUtils.isBlank(columnValue)) {
            return null;
        }
        final Collection<Integer> collection = new ArrayList<>();
        for (String s: columnValue.split(",")) {
            try {
                collection.add(Integer.valueOf(s));
            } catch (NumberFormatException e) {
                LOGGER.warn("Unable to convert value to Integer", e);
            }
        }
        return collection;
    }
}
