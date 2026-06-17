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

import alpine.config.AlpineConfigKeys;
import org.eclipse.microprofile.config.ConfigProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.Principal;

/**
 * Class is responsible for authenticating managed users against the internal user
 * database and optionally against a configured directory service (LDAP).
 *
 * @see AuthenticationService
 * @see ManagedUserAuthenticationService
 * @see LdapAuthenticationService
 * @author Steve Springett
 * @since 1.0.0
 */
public class Authenticator {

    private static final Logger LOGGER = LoggerFactory.getLogger(Authenticator.class);
    private static final boolean LDAP_ENABLED = ConfigProvider.getConfig().getValue(AlpineConfigKeys.LDAP_ENABLED, Boolean.class);

    private final String username;
    private final String password;

    /**
     * Constructs a new Authenticator object.
     * @param username the username to assert
     * @param password the password to assert
     */
    public Authenticator(final String username, final String password) {
        this.username = username;
        this.password = password;
    }

    /**
     * Attempts to authenticate the credentials internally first and if not  successful,
     * checks to see if LDAP is enabled or not. If enabled, a second attempt to authenticate
     * the credentials will be made, but this time against the directory service.
     * @return a Principal upon successful authentication
     * @throws AlpineAuthenticationException upon authentication failure
     * @since 1.0.0
     */
    public Principal authenticate() throws AlpineAuthenticationException {
        LOGGER.debug("Attempting to authenticate user: {}", username);
        final ManagedUserAuthenticationService userService = new ManagedUserAuthenticationService(username, password);
        try{
	        final Principal principal = userService.authenticate();
	        if (principal != null) {
	            return principal;
	        }
        }catch(AlpineAuthenticationException e){
            // If LDAP is enabled, a second attempt to authenticate the credentials will be
            // made against LDAP so we skip this validation exception. However, if the ManagedUser does exist, 
            // return the correct error
            if (!LDAP_ENABLED || e.getCauseType() != AlpineAuthenticationException.CauseType.INVALID_CREDENTIALS) {
                throw e;
            }
        }
        if (LDAP_ENABLED) {
            final LdapAuthenticationService ldapService = new LdapAuthenticationService(username, password);
            return ldapService.authenticate();
        }
        // This should never happen, but do not want to return null
        throw new AlpineAuthenticationException(AlpineAuthenticationException.CauseType.OTHER);
    }

}
