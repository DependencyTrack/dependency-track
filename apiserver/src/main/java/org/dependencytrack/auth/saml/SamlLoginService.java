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
package org.dependencytrack.auth.saml;

import alpine.model.ServiceAccount;
import alpine.model.auth.UserType;
import org.dependencytrack.auth.saml.SamlDao.LoginCode;
import org.dependencytrack.auth.saml.SamlDao.PendingAuthnRequest;
import org.dependencytrack.auth.saml.SamlDao.UserRow;
import org.dependencytrack.auth.saml.SamlMessages.AuthnRequest;
import org.dependencytrack.auth.saml.SamlResponseValidator.ValidatedAssertion;
import org.jspecify.annotations.Nullable;
import org.owasp.security.logging.SecurityMarkers;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.regex.Pattern;

import static org.dependencytrack.persistence.jdbi.JdbiFactory.inJdbiTransaction;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.useJdbiTransaction;

/// Runs the SAML login flow described in ADR 044.
///
/// @since 5.3.0
public final class SamlLoginService {

    private static final Logger LOGGER = LoggerFactory.getLogger(SamlLoginService.class);
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    static final Duration AUTHN_REQUEST_LIFETIME = Duration.ofMinutes(10);
    static final Duration LOGIN_CODE_LIFETIME = Duration.ofMinutes(1);

    // RFC 7636: S256 challenges are 43 characters of base64url, verifiers 43 to 128 unreserved characters.
    private static final Pattern CODE_CHALLENGE_PATTERN = Pattern.compile("^[A-Za-z0-9_-]{43}$");
    private static final Pattern CODE_VERIFIER_PATTERN = Pattern.compile("^[A-Za-z0-9._~-]{43,128}$");
    private static final Pattern CONTROL_CHARACTERS = Pattern.compile("\\p{Cc}");
    private static final int MAX_REDIRECT_PATH_LENGTH = 2048;
    private static final int MAX_USERNAME_LENGTH = 255;
    private static final int MAX_GROUP_NAME_LENGTH = 1024;

    /// The reason why a login was refused. Sent to the frontend, which shows a matching message.
    public enum FailureReason {
        /// The account does not exist, and user provisioning is disabled.
        UNMAPPED_ACCOUNT,
        /// Any other reason. Details are only logged.
        FAILED
    }

    public static final class LoginRefusedException extends Exception {

        private final FailureReason reason;

        LoginRefusedException(FailureReason reason, String message, @Nullable Throwable cause) {
            super(message, cause);
            this.reason = reason;
        }

        public FailureReason reason() {
            return reason;
        }
    }

    private final SamlConfig config;
    private final SamlIdpMetadataProvider metadataProvider;
    private final SamlResponseValidator responseValidator;
    private final Clock clock;

    SamlLoginService(
            SamlConfig config,
            SamlIdpMetadataProvider metadataProvider,
            SamlResponseValidator responseValidator,
            Clock clock) {
        this.config = config;
        this.metadataProvider = metadataProvider;
        this.responseValidator = responseValidator;
        this.clock = clock;
    }

    public SamlLoginService(SamlConfig config) {
        this(config, new SamlIdpMetadataProvider(config), new SamlResponseValidator(config), Clock.systemUTC());
    }

    public SamlConfig config() {
        return config;
    }

    public static boolean isValidCodeChallenge(@Nullable String codeChallenge) {
        return codeChallenge != null
                && CODE_CHALLENGE_PATTERN.matcher(codeChallenge).matches();
    }

    public static boolean isValidCodeVerifier(@Nullable String codeVerifier) {
        return codeVerifier != null
                && CODE_VERIFIER_PATTERN.matcher(codeVerifier).matches();
    }

    /// Returns the given path when it is safe to redirect to within the frontend, otherwise `null`.
    static @Nullable String sanitizeRedirectPath(@Nullable String path) {
        if (path == null
                || path.length() > MAX_REDIRECT_PATH_LENGTH
                || !path.startsWith("/")
                || path.startsWith("//")
                || path.contains("\\")
                || CONTROL_CHARACTERS.matcher(path).find()) {
            return null;
        }
        return path;
    }

    /// Creates an authentication request, and remembers it until the IdP responds.
    ///
    /// @return The URL of the IdP to redirect the browser to.
    public URI startLogin(String codeChallenge, @Nullable String redirectPath) throws SamlException {
        final Instant now = clock.instant();
        final AuthnRequest request = SamlMessages.createAuthnRequest(config, metadataProvider.get(), now);

        useJdbiTransaction(handle -> handle.attach(SamlDao.class)
                .createAuthnRequest(
                        request.id(),
                        codeChallenge,
                        sanitizeRedirectPath(redirectPath),
                        now.plus(AUTHN_REQUEST_LIFETIME)));

        return request.redirectUrl();
    }

    /// The result of a successful login at the assertion consumer service.
    ///
    /// @param code The one-time code to exchange for a session token.
    /// @param redirectPath The frontend path that the user wanted to visit.
    public record CompletedLogin(
            String username, String code, @Nullable String redirectPath) {}

    /// Verifies a response from the IdP, provisions the user and their groups and teams,
    /// and creates a one-time code.
    public CompletedLogin completeLogin(String encodedResponse) throws LoginRefusedException {
        final ValidatedAssertion assertion;
        try {
            assertion = responseValidator.validate(encodedResponse, metadataProvider.get());
        } catch (SamlException e) {
            throw new LoginRefusedException(FailureReason.FAILED, "Response refused: " + e.getMessage(), e);
        }

        final String username = resolveUsername(assertion);
        final String email = resolveEmail(assertion);
        final List<String> groups = resolveGroups(assertion);

        final byte[] codeBytes = new byte[32];
        SECURE_RANDOM.nextBytes(codeBytes);
        final String code = Base64.getUrlEncoder().withoutPadding().encodeToString(codeBytes);

        // Consume the request in its own transaction, so that it is gone even when the login is refused later.
        final Instant now = clock.instant();
        final PendingAuthnRequest request =
                inJdbiTransaction(handle -> handle.attach(SamlDao.class).consumeAuthnRequest(assertion.inResponseTo()));
        if (request == null || !now.isBefore(request.expiresAt())) {
            throw new LoginRefusedException(
                    FailureReason.FAILED,
                    "Response refers to unknown or expired request " + assertion.inResponseTo(),
                    null);
        }

        inJdbiTransaction(handle -> {
            final var dao = handle.attach(SamlDao.class);
            final long userId = provisionUser(dao, username, email, groups);
            dao.createLoginCode(sha256Hex(code), userId, request.codeChallenge(), now.plus(LOGIN_CODE_LIFETIME));
            return userId;
        });

        return new CompletedLogin(username, code, request.redirectPath());
    }

    /// Exchanges a one-time code for the ID of the user that logged in.
    ///
    /// @return The user ID, or `null` when the code is unknown, expired, or the verifier does not match.
    public static @Nullable Long exchangeCode(String code, String codeVerifier, Instant now) {
        final LoginCode loginCode =
                inJdbiTransaction(handle -> handle.attach(SamlDao.class).consumeLoginCode(sha256Hex(code)));
        if (loginCode == null || !now.isBefore(loginCode.expiresAt())) {
            return null;
        }

        final byte[] expectedChallenge = loginCode.codeChallenge().getBytes(StandardCharsets.US_ASCII);
        final byte[] actualChallenge = Base64.getUrlEncoder()
                .withoutPadding()
                .encode(sha256(codeVerifier.getBytes(StandardCharsets.US_ASCII)));
        if (!MessageDigest.isEqual(expectedChallenge, actualChallenge)) {
            return null;
        }

        return loginCode.userId();
    }

    public static int deleteExpired() {
        return inJdbiTransaction(handle -> {
            final var dao = handle.attach(SamlDao.class);
            return dao.deleteExpiredAuthnRequests() + dao.deleteExpiredLoginCodes();
        });
    }

    private long provisionUser(SamlDao dao, String username, @Nullable String email, List<String> groups)
            throws LoginRefusedException {
        final UserRow existingUser = dao.getUser(username);

        final long userId;
        final boolean created;
        if (existingUser != null) {
            // Never let an IdP user take over an account of another type with the same name.
            if (!UserType.SAML.name().equals(existingUser.type())) {
                throw new LoginRefusedException(
                        FailureReason.FAILED,
                        "Username %s is already used by a user of type %s".formatted(username, existingUser.type()),
                        null);
            }
            userId = existingUser.id();
            created = false;
            if (config.emailAttribute() != null) {
                dao.updateEmail(userId, email);
            }
        } else if (config.userProvisioning()) {
            userId = dao.createUser(username, email);
            created = true;
            LOGGER.info(SecurityMarkers.SECURITY_AUDIT, "Provisioned SAML user {}", username);
        } else {
            throw new LoginRefusedException(
                    FailureReason.UNMAPPED_ACCOUNT,
                    "User %s does not exist, and user provisioning is disabled".formatted(username),
                    null);
        }

        if (config.groupProvisioning()) {
            for (final String groupName : dao.createGroups(groups)) {
                LOGGER.info(
                        SecurityMarkers.SECURITY_AUDIT,
                        "Created SAML group {} from groups of user {}",
                        groupName,
                        username);
            }
        }

        if (config.teamSynchronization()) {
            dao.synchronizeTeams(userId, groups);
        } else if (created) {
            dao.addToTeams(userId, config.defaultTeams());
        }

        return userId;
    }

    private String resolveUsername(ValidatedAssertion assertion) throws LoginRefusedException {
        final String username;
        if (config.usernameAttribute() != null) {
            final List<String> values = assertion.attributeValues(config.usernameAttribute());
            if (values.size() != 1) {
                throw new LoginRefusedException(
                        FailureReason.FAILED,
                        "Expected exactly one value of username attribute %s, but got %d"
                                .formatted(config.usernameAttribute(), values.size()),
                        null);
            }
            username = values.getFirst().strip();
        } else {
            username = assertion.nameId();
        }

        if (username.isEmpty()
                || username.length() > MAX_USERNAME_LENGTH
                || CONTROL_CHARACTERS.matcher(username).find()) {
            throw new LoginRefusedException(FailureReason.FAILED, "Username is empty, too long, or invalid", null);
        }
        if (ServiceAccount.hasReservedPrefix(username)) {
            throw new LoginRefusedException(
                    FailureReason.FAILED,
                    "Username %s uses the prefix reserved for service accounts".formatted(username),
                    null);
        }

        return username;
    }

    private @Nullable String resolveEmail(ValidatedAssertion assertion) {
        if (config.emailAttribute() == null) {
            return null;
        }
        return assertion.attributeValues(config.emailAttribute()).stream()
                .map(String::strip)
                .filter(email -> !email.isEmpty()
                        && email.length() <= 255
                        && !CONTROL_CHARACTERS.matcher(email).find())
                .findFirst()
                .orElse(null);
    }

    private List<String> resolveGroups(ValidatedAssertion assertion) {
        if (config.groupsAttribute() == null) {
            return List.of();
        }
        return assertion.attributeValues(config.groupsAttribute()).stream()
                .filter(group -> group.length() <= MAX_GROUP_NAME_LENGTH)
                .distinct()
                .toList();
    }

    private static String sha256Hex(String value) {
        return HexFormat.of().formatHex(sha256(value.getBytes(StandardCharsets.UTF_8)));
    }

    private static byte[] sha256(byte[] value) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(value);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
