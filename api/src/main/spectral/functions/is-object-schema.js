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
'use strict';

const assertObjectSchema = (schema) => {
    if (schema.type !== 'object') {
        throw 'Schema type is not `object`';
    }

    // Require some properties to be defined when additionalProperties
    // is used. There should never be responses with properties that
    // are completely unknown.
    if (schema.additionalProperties && !schema.properties) {
        throw 'Schema is a map';
    }
};

const check = (schema) => {
    const combinedSchemas = [...(schema.anyOf || []), ...(schema.oneOf || []), ...(schema.allOf || [])];
    if (combinedSchemas.length > 0) {
        combinedSchemas.forEach(check);
    } else {
        assertObjectSchema(schema);
    }
};

export default (targetValue) => {
    try {
        check(targetValue);
    } catch (ex) {
        return [
            {
                message: ex,
            },
        ];
    }
};