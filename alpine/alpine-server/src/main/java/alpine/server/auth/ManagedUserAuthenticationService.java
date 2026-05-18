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

import alpine.model.ManagedUser;
import alpine.persistence.AlpineQueryManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.Principal;

/**
 * Class that performs authentication against internally managed users.
 *
 * @author Steve Springett
 * @since 1.0.0
 */
public class ManagedUserAuthenticationService implements AuthenticationService {

    private static final Logger LOGGER = LoggerFactory.getLogger(ManagedUserAuthenticationService.class);
    private final String username;
    private final String password;

    /**
     * Authentication service validates credentials against internally managed users.
     * @param username the asserted username
     * @param password the asserted password
     * @since 1.0.0
     */
    public ManagedUserAuthenticationService(final String username, final String password) {
        this.username = username;
        this.password = password;
    }

    /**
     * Returns whether the username/password combo was specified or not. In
     * this case, since the constructor requires it, this method will always
     * return true.
     * @return always will return true
     * @since 1.0.0
     */
    public boolean isSpecified() {
        return true;
    }

    /**
     * Authenticates the username/password combo against the directory service
     * and returns a Principal if authentication is successful. Otherwise,
     * returns an AuthenticationException.
     *
     * @return a Principal if authentication was successful
     * @throws AlpineAuthenticationException when authentication is unsuccessful
     * @since 1.0.0
     */
    public Principal authenticate() throws AlpineAuthenticationException {
        LOGGER.debug("Attempting to authenticate user: {}", username);
        try (AlpineQueryManager qm = new AlpineQueryManager()) {
            final ManagedUser user = qm.getManagedUser(username);
            if (user != null) {
                if (PasswordService.matches(password.toCharArray(), user)) {
                    if (user.isSuspended()) {
                        throw new AlpineAuthenticationException(AlpineAuthenticationException.CauseType.SUSPENDED, user);
                    }
                    if (user.isForcePasswordChange()) {
                        throw new AlpineAuthenticationException(AlpineAuthenticationException.CauseType.FORCE_PASSWORD_CHANGE, user);
                    }
                    return user;
                }
            } else {
                // Hash the provided password anyway to prevent different timings
                // giving away the existence of a user.
                char[] _ = PasswordService.createHash(password.toCharArray());
            }
        }
        throw new AlpineAuthenticationException(AlpineAuthenticationException.CauseType.INVALID_CREDENTIALS);
    }

}
