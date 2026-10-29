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

import org.jdbi.v3.sqlobject.SqlObject;
import org.jdbi.v3.sqlobject.config.RegisterConstructorMapper;
import org.jdbi.v3.sqlobject.customizer.Bind;
import org.jdbi.v3.sqlobject.statement.GetGeneratedKeys;
import org.jdbi.v3.sqlobject.statement.SqlUpdate;
import org.jspecify.annotations.Nullable;

import java.time.Instant;

/// State of logins in progress: pending authentication requests and one-time codes.
///
/// @since 5.3.0
public interface SamlLoginDao extends SqlObject {

    @SqlUpdate("""
        INSERT INTO "SAML_AUTHN_REQUEST" ("ID", "CODE_CHALLENGE", "REDIRECT_PATH", "EXPIRES_AT")
        VALUES (:id, :codeChallenge, :redirectPath, :expiresAt)
        """)
    void createAuthnRequest(
            @Bind String id, @Bind String codeChallenge, @Bind @Nullable String redirectPath, @Bind Instant expiresAt);

    record PendingAuthnRequest(
            String codeChallenge, @Nullable String redirectPath, Instant expiresAt) {}

    /// Deletes a pending authentication request, so that it cannot be answered twice.
    @SqlUpdate("""
        DELETE
          FROM "SAML_AUTHN_REQUEST"
         WHERE "ID" = :id
        RETURNING "CODE_CHALLENGE", "REDIRECT_PATH", "EXPIRES_AT"
        """)
    @GetGeneratedKeys
    @RegisterConstructorMapper(PendingAuthnRequest.class)
    @Nullable
    PendingAuthnRequest consumeAuthnRequest(@Bind String id);

    @SqlUpdate("""
        INSERT INTO "SAML_LOGIN_CODE" ("CODE_HASH", "USER_ID", "CODE_CHALLENGE", "EXPIRES_AT")
        VALUES (:codeHash, :userId, :codeChallenge, :expiresAt)
        """)
    void createLoginCode(@Bind String codeHash, @Bind long userId, @Bind String codeChallenge, @Bind Instant expiresAt);

    record LoginCode(long userId, String codeChallenge, Instant expiresAt) {}

    /// Deletes a login code, so that it cannot be used twice.
    @SqlUpdate("""
        DELETE
          FROM "SAML_LOGIN_CODE"
         WHERE "CODE_HASH" = :codeHash
        RETURNING "USER_ID", "CODE_CHALLENGE", "EXPIRES_AT"
        """)
    @GetGeneratedKeys
    @RegisterConstructorMapper(LoginCode.class)
    @Nullable
    LoginCode consumeLoginCode(@Bind String codeHash);

    @SqlUpdate("""
        DELETE FROM "SAML_AUTHN_REQUEST" WHERE "EXPIRES_AT" < NOW()
        """)
    int deleteExpiredAuthnRequests();

    @SqlUpdate("""
        DELETE FROM "SAML_LOGIN_CODE" WHERE "EXPIRES_AT" < NOW()
        """)
    int deleteExpiredLoginCodes();
}
