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

/*
Minimal required problem json schema:

type: object
properties:
  type:
    type: string
    format: uri-reference
  title:
    type: string
  status:
    type: integer
    format: int32
  detail:
    type: string
  instance:
    type: string
*/

const assertProblemSchema = (schema) => {
    if (schema.type !== 'object') {
        throw "Problem json must have type 'object'";
    }
    const type = (schema.properties || {}).type || {};
    if (type.type !== 'string' || type.format !== 'uri-reference') {
        throw "Problem json must have property 'type' with type 'string' and format 'uri-reference'";
    }
    const title = (schema.properties || {}).title || {};
    if (title.type !== 'string') {
        throw "Problem json must have property 'title' with type 'string'";
    }
    const status = (schema.properties || {}).status || {};
    if (status.type !== 'integer' || status.format !== 'int32') {
        throw "Problem json must have property 'status' with type 'integer' and format 'int32'";
    }
    const detail = (schema.properties || {}).detail || {};
    if (detail.type !== 'string') {
        throw "Problem json must have property 'detail' with type 'string'";
    }
    const instance = (schema.properties || {}).instance || {};
    if (instance.type !== 'string') {
        throw "Problem json must have property 'instance' with type 'string'";
    }
};

/*
 * Merge list of schema definitions of type = 'object'.
 * Return object will have a super set of attributes 'properties' and 'required'.
 */
const mergeObjectDefinitions = (allOfTypes) => {
    if (allOfTypes.filter((item) => item.type !== 'object').length !== 0) {
        throw "All schema definitions must be of type 'object'";
    }

    return allOfTypes.reduce((acc, item) => {
        return {
            type: 'object',
            properties: { ...(acc.properties || {}), ...(item.properties || {}) },
            required: [...(acc.required || []), ...(item.required || [])],
        };
    }, {});
};

const check = (schema) => {
    const combinedSchemas = [...(schema.anyOf || []), ...(schema.oneOf || [])];
    if (schema.allOf) {
        const mergedAllOf = mergeObjectDefinitions(schema.allOf);
        if (mergedAllOf) {
            combinedSchemas.push(mergedAllOf);
        }
    }

    if (combinedSchemas.length > 0) {
        combinedSchemas.forEach(check);
    } else {
        assertProblemSchema(schema);
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