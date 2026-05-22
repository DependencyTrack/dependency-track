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
package alpine.config;

/**
 * @since 5.0.0
 */
public final class AlpineConfigKeys {

    public static final String BCRYPT_ROUNDS = "dt.bcrypt.rounds";
    public static final String LDAP_ENABLED = "dt.ldap.enabled";
    public static final String LDAP_SERVER_URL = "dt.ldap.server.url";
    public static final String LDAP_BASEDN = "dt.ldap.basedn";
    public static final String LDAP_SECURITY_AUTH = "dt.ldap.security.auth";
    public static final String LDAP_BIND_USERNAME = "dt.ldap.bind.username";
    public static final String LDAP_BIND_PASSWORD = "dt.ldap.bind.password";
    public static final String LDAP_AUTH_USERNAME_FMT = "dt.ldap.auth.username.format";
    public static final String LDAP_ATTRIBUTE_NAME = "dt.ldap.attribute.name";
    public static final String LDAP_ATTRIBUTE_MAIL = "dt.ldap.attribute.mail";
    public static final String LDAP_GROUPS_FILTER = "dt.ldap.groups.filter";
    public static final String LDAP_USER_GROUPS_FILTER = "dt.ldap.user.groups.filter";
    public static final String LDAP_GROUPS_SEARCH_FILTER = "dt.ldap.groups.search.filter";
    public static final String LDAP_USERS_SEARCH_FILTER = "dt.ldap.users.search.filter";
    public static final String LDAP_USER_PROVISIONING = "dt.ldap.user.provisioning";
    public static final String LDAP_TEAM_SYNCHRONIZATION = "dt.ldap.team.synchronization";
    public static final String OIDC_ENABLED = "dt.oidc.enabled";
    public static final String OIDC_ISSUER = "dt.oidc.issuer";
    public static final String OIDC_CLIENT_ID = "dt.oidc.client.id";
    public static final String OIDC_USERNAME_CLAIM = "dt.oidc.username.claim";
    public static final String OIDC_USER_PROVISIONING = "dt.oidc.user.provisioning";
    public static final String OIDC_TEAM_SYNCHRONIZATION = "dt.oidc.team.synchronization";
    public static final String OIDC_TEAMS_CLAIM = "dt.oidc.teams.claim";
    public static final String OIDC_TEAMS_DEFAULT = "dt.oidc.teams.default";
    public static final String OIDC_AUTH_CUSTOMIZER = "dt.oidc.auth.customizer";
    public static final String HTTP_PROXY_ADDRESS = "dt.http.proxy.address";
    public static final String HTTP_PROXY_PORT = "dt.http.proxy.port";
    public static final String HTTP_PROXY_USERNAME = "dt.http.proxy.username";
    public static final String HTTP_PROXY_PASSWORD = "dt.http.proxy.password";
    public static final String NO_PROXY = "dt.no.proxy";
    public static final String HTTP_TIMEOUT_CONNECTION = "dt.http.timeout.connection";
    public static final String CORS_ENABLED = "dt.cors.enabled";
    public static final String CORS_ALLOW_ORIGIN = "dt.cors.allow.origin";
    public static final String CORS_ALLOW_METHODS = "dt.cors.allow.methods";
    public static final String CORS_ALLOW_HEADERS = "dt.cors.allow.headers";
    public static final String CORS_EXPOSE_HEADERS = "dt.cors.expose.headers";
    public static final String CORS_ALLOW_CREDENTIALS = "dt.cors.allow.credentials";
    public static final String CORS_MAX_AGE = "dt.cors.max.age";
    public static final String API_KEY_PREFIX = "dt.api.key.prefix";

    public static final String BUILD_INFO_APPLICATION_NAME = "alpine.build-info.application.name";
    public static final String BUILD_INFO_APPLICATION_VERSION = "alpine.build-info.application.version";
    public static final String BUILD_INFO_APPLICATION_TIMESTAMP = "alpine.build-info.application.timestamp";
    public static final String BUILD_INFO_APPLICATION_UUID = "alpine.build-info.application.uuid";
    public static final String BUILD_INFO_FRAMEWORK_NAME = "alpine.build-info.framework.name";
    public static final String BUILD_INFO_FRAMEWORK_VERSION = "alpine.build-info.framework.version";
    public static final String BUILD_INFO_FRAMEWORK_TIMESTAMP = "alpine.build-info.framework.timestamp";
    public static final String BUILD_INFO_FRAMEWORK_UUID = "alpine.build-info.framework.uuid";

    private AlpineConfigKeys() {
    }

}
