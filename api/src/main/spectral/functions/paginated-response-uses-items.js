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

export default (schema) => {
    // Spectral resolves $refs but does not merge allOf, which is how list responses extend paginated-response.yaml.
    const parts = [schema, ...(schema.allOf || [])];
    const properties = Object.assign({}, ...parts.map(part => part.properties || {}));
    const required = parts.flatMap(part => part.required || []);

    if (!('next_page_token' in properties)) {
        return;
    }

    if (!properties.items || properties.items.type !== 'array') {
        return [
            {
                message: 'Paginated response must have an "items" property of type "array"',
            },
        ];
    }

    if (!required.includes('items')) {
        return [
            {
                message: 'Paginated response must declare "items" as required',
            },
        ];
    }

    const otherArrays = Object.keys(properties).filter(name => name !== 'items' && properties[name].type === 'array');
    if (otherArrays.length > 0) {
        return [
            {
                message: `Paginated response must not have array properties other than "items", found: ${otherArrays.join(', ')}`,
            },
        ];
    }
};
