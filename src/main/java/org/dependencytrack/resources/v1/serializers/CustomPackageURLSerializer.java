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
package org.dependencytrack.resources.v1.serializers;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.ser.std.StdSerializer;
import com.github.packageurl.PackageURL;
import java.io.IOException;

/**
 * This class serializes a PackageURL by returning the canonicalized form
 * of the object rather than the individual parts.
 *
 * @author Steve Springett
 * @since 3.0.0
 */
public class CustomPackageURLSerializer extends StdSerializer<PackageURL> {

    public CustomPackageURLSerializer() {
        this(null);
    }

    public CustomPackageURLSerializer(Class<PackageURL> t) {
        super(t);
    }

    @Override
    public void serialize(PackageURL purl, JsonGenerator gen, SerializerProvider arg2)
            throws IOException, JsonProcessingException {
        gen.writeString(purl.canonicalize());
    }

}
