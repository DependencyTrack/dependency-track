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

import alpine.model.ApiKey;
import alpine.persistence.AlpineQueryManager;
import alpine.security.ApiKeyDecoder;
import alpine.security.InvalidApiKeyFormatException;
import org.glassfish.jersey.server.ContainerRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.naming.AuthenticationException;
import java.security.MessageDigest;
import java.security.Principal;

/**
 * Authentication service that validates API keys.
 *
 * @author Steve Springett
 * @since 1.0.0
 */
public class ApiKeyAuthenticationService implements AuthenticationService {

    private static final Logger LOGGER = LoggerFactory.getLogger(ApiKeyAuthenticationService.class);

    private final String assertedApiKey;

    /**
     * Given the specified ContainerRequest, the constructor retrieves a header
     * named 'X-Api-Key', if it exists.
     * @param request the ContainerRequest object
     * @since 1.0.0
     */
    public ApiKeyAuthenticationService(final ContainerRequest request) {
        this.assertedApiKey = request.getHeaderString("X-Api-Key");
    }

    /**
     * Returns whether an API key was specified or not.
     * @return true if API key was specified, false if not
     * @since 1.0.0
     */
    public boolean isSpecified() {
        return assertedApiKey != null;
    }

    /**
     * Authenticates the API key (if it was specified in the X-Api-Key header)
     * and returns a Principal if authentication is successful.
     * Otherwise, throws an AuthenticationException.
     * @return a Principal of which ApiKey is an instance of
     * @throws AuthenticationException upon an authentication failure
     * @since 1.0.0
     */
    public Principal authenticate() throws AuthenticationException {
        final ApiKey decodedApiKey;
        try {
            decodedApiKey = ApiKeyDecoder.decode(assertedApiKey);
        } catch (InvalidApiKeyFormatException e) {
            LOGGER.debug("Format of the provided API key is invalid", e);
            throw new AuthenticationException();
        }

        try (final var qm = new AlpineQueryManager()) {
            final ApiKey apiKey = qm.getApiKeyByPublicId(decodedApiKey.getPublicId());
            if (apiKey == null) {
                LOGGER.debug("No API key found for public ID {}", decodedApiKey.getPublicId());
                throw new AuthenticationException();
            }

            if (!MessageDigest.isEqual(decodedApiKey.getSecretHash().getBytes(), apiKey.getSecretHash().getBytes())) {
                LOGGER.debug("API key secret hashes do not match");
                throw new AuthenticationException();
            }

            return apiKey;
        }
    }

}
