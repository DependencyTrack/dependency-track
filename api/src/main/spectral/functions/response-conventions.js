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

export default (responses, opts) => {
    const method = opts.method;
    const errors = [];

    switch (method) {
        case 'post': {
            if (!('201' in responses) && !('202' in responses) && !('204' in responses)) {
                errors.push({message: 'POST must return 201 (Created), 202 (Accepted), or 204 (No Content)'});
            }
            if ('200' in responses) {
                errors.push({message: 'POST must not return 200; use 201, 202, or 204'});
            }
            if ('201' in responses && (!responses['201'].headers || !responses['201'].headers['Location'])) {
                errors.push({message: 'POST 201 response must include a Location header'});
            }
            if ('202' in responses && (!responses['202'].headers || !responses['202'].headers['Location'])) {
                errors.push({message: 'POST 202 response must include a Location header'});
            }
            break;
        }
        case 'put': {
            if (!('204' in responses)) {
                errors.push({message: 'PUT must return 204 (No Content)'});
            }
            break;
        }
        case 'patch': {
            if (!('200' in responses) && !('204' in responses)) {
                errors.push({message: 'PATCH must return 200 (OK) or 204 (No Content)'});
            }
            if ('200' in responses && !responses['200'].content) {
                errors.push({message: 'PATCH 200 response must include a response body'});
            }
            break;
        }
        case 'delete': {
            if (!('204' in responses)) {
                errors.push({message: 'DELETE must return 204 (No Content)'});
            }
            break;
        }
    }

    return errors.length > 0 ? errors : undefined;
};
