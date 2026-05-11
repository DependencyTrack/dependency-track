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
package org.dependencytrack.cache.api;

/**
 * Internal exception thrown by {@link Cache#get(String)} to prevent
 * {@code null} values from being cached on cache miss.
 * <p>
 * This exception doesn't populate the stack trace,
 * making it cheaper to throw than any normal exception.
 * <p>
 * It is not intended to be exposed to callers.
 *
 * @since 5.0.0
 */
final class CacheMissException extends RuntimeException {

    static final CacheMissException INSTANCE = new CacheMissException();

    private CacheMissException() {
        super(null, null, /* enableSuppression */ false, /* writableStackTrace */ false);
    }

}
