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
package org.dependencytrack.support.jdbi.exception;

import org.jdbi.v3.core.HandleCallback;
import org.jdbi.v3.core.HandleCallbackDecorator;

final class ExceptionTranslationCallbackDecorator implements HandleCallbackDecorator {

    private final HandleCallbackDecorator delegate;

    ExceptionTranslationCallbackDecorator(HandleCallbackDecorator delegate) {
        this.delegate = delegate;
    }

    @Override
    public <R, X extends Exception> HandleCallback<R, X> decorate(HandleCallback<R, X> callback) {
        final HandleCallback<R, X> delegated = delegate.decorate(callback);
        return handle -> {
            try {
                return delegated.withHandle(handle);
            } catch (RuntimeException e) {
                final ConstraintViolationException translated = ConstraintViolationException.of(e);
                if (translated != null) {
                    throw translated;
                }
                throw e;
            }
        };
    }

}
