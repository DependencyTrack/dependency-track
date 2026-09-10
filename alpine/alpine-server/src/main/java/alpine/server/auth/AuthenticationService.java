/*
 * This file is part of Alpine.
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
package alpine.server.auth;

import jakarta.annotation.Nullable;
import javax.naming.AuthenticationException;

/**
 * Interface that defines an authentication service.
 *
 * @param <T> Type of the principal this service authenticates.
 * @author Steve Springett
 * @since 1.0.0
 */
public interface AuthenticationService<T> {

    /**
     * Defines a method which returns if the specified piece of
     * data, required to perform authentication is present.
     * @return true if the authentication data was specified, false if not
     * @since 1.0.0
     */
    boolean isSpecified();

    /**
     * Defines an authentication method which returns a principal
     * if authentication is successful or an AuthorizationException
     * if not.
     * @return the authenticated principal
     * @throws AuthenticationException an authentication failure
     * @since 1.0.0
     */
    @Nullable
    T authenticate() throws AuthenticationException;

}
