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

import alpine.common.validation.LdapStringSanitizer;
import alpine.config.AlpineConfigKeys;
import alpine.model.LdapUser;
import org.eclipse.microprofile.config.Config;
import org.eclipse.microprofile.config.ConfigProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.naming.CommunicationException;
import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.PartialResultException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.InitialLdapContext;
import javax.naming.ldap.LdapContext;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Hashtable;
import java.util.List;

/**
 * A convenience wrapper for LDAP connections and commons LDAP tasks.
 *
 * @since 1.4.0
 */
public class LdapConnectionWrapper {

    private static final Logger LOGGER = LoggerFactory.getLogger(LdapConnectionWrapper.class);

    private final String bindUsername;
    private final String bindPassword;
    private final String securityAuth;
    private final String authUsernameFmt;
    private final String userGroupsFilter;
    private final String groupsSearchFilter;
    private final boolean ldapEnabled;
    private final String ldapUrl;
    private final String baseDn;
    private final String attributeMail;
    private final String attributeName;
    private final boolean userProvisioning;
    private final boolean teamSynchronization;
    private final boolean ldapSslTls;

    public LdapConnectionWrapper() {
        this(ConfigProvider.getConfig());
    }

    public LdapConnectionWrapper(Config config) {
        this.bindUsername = config.getOptionalValue(AlpineConfigKeys.LDAP_BIND_USERNAME, String.class).orElse(null);
        this.bindPassword = config.getOptionalValue(AlpineConfigKeys.LDAP_BIND_PASSWORD, String.class).orElse(null);
        this.securityAuth = config.getOptionalValue(AlpineConfigKeys.LDAP_SECURITY_AUTH, String.class).orElse(null);
        this.authUsernameFmt = config.getOptionalValue(AlpineConfigKeys.LDAP_USERNAME_FORMAT, String.class).orElse(null);
        this.userGroupsFilter = config.getOptionalValue(AlpineConfigKeys.LDAP_USER_GROUPS_FILTER, String.class).orElse(null);
        this.groupsSearchFilter = config.getOptionalValue(AlpineConfigKeys.LDAP_GROUP_SEARCH_FILTER, String.class).orElse(null);
        this.ldapEnabled = config.getValue(AlpineConfigKeys.LDAP_ENABLED, Boolean.class);
        this.ldapUrl = config.getOptionalValue(AlpineConfigKeys.LDAP_SERVER_URL, String.class).orElse(null);
        this.baseDn = config.getOptionalValue(AlpineConfigKeys.LDAP_BASEDN, String.class).orElse(null);
        this.attributeMail = config.getValue(AlpineConfigKeys.LDAP_MAIL_ATTRIBUTE, String.class);
        this.attributeName = config.getValue(AlpineConfigKeys.LDAP_NAME_ATTRIBUTE, String.class);
        this.userProvisioning = config.getValue(AlpineConfigKeys.LDAP_USER_PROVISIONING, Boolean.class);
        this.teamSynchronization = config.getValue(AlpineConfigKeys.LDAP_TEAM_SYNCHRONIZATION, Boolean.class);
        this.ldapSslTls = this.ldapUrl != null && !this.ldapUrl.isBlank() && this.ldapUrl.startsWith("ldaps:");
    }

    public boolean isLdapConfigured() {
        return ldapEnabled && ldapUrl != null && !ldapUrl.isBlank();
    }

    public String getAttributeMail() {
        return attributeMail;
    }

    public boolean isUserProvisioningEnabled() {
        return userProvisioning;
    }

    public boolean isTeamSynchronizationEnabled() {
        return teamSynchronization;
    }

    /**
     * Asserts a users credentials. Returns an LdapContext if assertion is successful
     * or an exception for any other reason.
     *
     * @param userDn   the users DN to assert
     * @param password the password to assert
     * @return the LdapContext upon a successful connection
     * @throws NamingException when unable to establish a connection
     * @since 1.4.0
     */
    public LdapContext createLdapContext(final String userDn, final String password) throws NamingException {
        LOGGER.debug("Creating LDAP context for: {}", userDn);
        if (userDn == null || userDn.isEmpty() || password == null || password.isEmpty()) {
            throw new NamingException("Username or password cannot be empty or null");
        }
        final Hashtable<String, String> env = new Hashtable<>();
        if (securityAuth != null && !securityAuth.isBlank()) {
            env.put(Context.SECURITY_AUTHENTICATION, securityAuth);
        }
        env.put(Context.SECURITY_PRINCIPAL, userDn);
        env.put(Context.SECURITY_CREDENTIALS, password);
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.PROVIDER_URL, ldapUrl);
        if (ldapSslTls) {
            env.put("java.naming.ldap.factory.socket", "alpine.security.crypto.RelaxedSSLSocketFactory");
        }
        try {
            return new InitialLdapContext(env, null);
        } catch (CommunicationException e) {
            LOGGER.error("Failed to connect to directory server", e);
            throw e;
        }
    }

    /**
     * Creates a DirContext with the applications configuration settings.
     *
     * @return a DirContext
     * @throws NamingException if an exception is thrown
     * @since 1.4.0
     */
    public DirContext createDirContext() throws NamingException {
        LOGGER.debug("Creating directory service context (DirContext)");
        final Hashtable<String, String> env = new Hashtable<>();
        if (bindUsername != null && !bindUsername.isBlank()) {
            env.put(Context.SECURITY_PRINCIPAL, bindUsername);
            if (bindPassword != null && !bindPassword.isBlank()) {
                env.put(Context.SECURITY_CREDENTIALS, bindPassword);
            }
        }
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.PROVIDER_URL, ldapUrl);
        if (ldapSslTls) {
            env.put("java.naming.ldap.factory.socket", "alpine.security.crypto.RelaxedSSLSocketFactory");
        }
        return new InitialDirContext(env);
    }

    /**
     * Retrieves a list of all groups the user is a member of.
     *
     * @param dirContext a DirContext
     * @param ldapUser   the LdapUser to retrieve group membership for
     * @return A list of Strings representing the fully qualified DN of each group
     * @throws NamingException if an exception is thrown
     * @since 1.4.0
     */
    public List<String> getGroups(final DirContext dirContext, final LdapUser ldapUser) throws NamingException {
        LOGGER.debug("Retrieving groups for: {}", ldapUser.getDN());
        final List<String> groupDns = new ArrayList<>();
        final String searchFilter = variableSubstitution(userGroupsFilter, ldapUser);
        final SearchControls sc = new SearchControls();
        sc.setSearchScope(SearchControls.SUBTREE_SCOPE);
        final NamingEnumeration<SearchResult> ne = dirContext.search(baseDn, searchFilter, sc);
        while (hasMoreEnum(ne)) {
            final SearchResult result = ne.next();
            groupDns.add(result.getNameInNamespace());
            LOGGER.debug("Found group: {} for user: {}", result.getNameInNamespace(), ldapUser.getDN());
        }
        closeQuietly(ne);
        return groupDns;
    }

    /**
     * Retrieves a list of all the groups in the directory that match the specified groupName.
     * This is a convenience method which wraps {@link #search(DirContext, String, String)}.
     *
     * @param dirContext a DirContext
     * @param groupName  the name (or partial name) of the group to to search for
     * @return A list of Strings representing the fully qualified DN of each group
     * @throws NamingException if an exception if thrown
     * @since 1.5.0
     */
    public List<String> searchForGroupName(final DirContext dirContext, String groupName) throws NamingException {
        return search(dirContext, groupsSearchFilter, groupName);
    }

    /**
     * Retrieves a list of all the entries in the directory that match the specified filter and searchTerm
     *
     * @param dirContext a DirContext
     * @param filter     a pre-defined ldap filter containing a {SEARCH_TERM} as a placeholder
     * @param searchTerm the search term to query on
     * @return A list of Strings representing the fully qualified DN of each group
     * @throws NamingException if an exception if thrown
     * @since 1.5.0
     */
    public List<String> search(final DirContext dirContext, final String filter, final String searchTerm) throws NamingException {
        LOGGER.debug("Searching / filter: {} searchTerm: {}", filter, searchTerm);
        final List<String> entityDns = new ArrayList<>();
        final SearchControls sc = new SearchControls();
        sc.setSearchScope(SearchControls.SUBTREE_SCOPE);
        final String searchFor = searchTermSubstitution(filter, searchTerm);
        LOGGER.debug("Searching for: {}", searchFor);
        final NamingEnumeration<SearchResult> ne = dirContext.search(baseDn, searchFor, sc);
        while (hasMoreEnum(ne)) {
            final SearchResult result = ne.next();
            entityDns.add(result.getNameInNamespace());
            LOGGER.debug("Found: {}", result.getNameInNamespace());
        }
        closeQuietly(ne);
        return entityDns;
    }

    /**
     * Performs a search for the specified username. Internally, this method queries on
     * the attribute defined by {@link AlpineConfigKeys#LDAP_NAME_ATTRIBUTE}.
     *
     * @param ctx      the DirContext to use
     * @param username the username to query on
     * @return a list of SearchResult objects. If the username is found, the list should typically only contain one result.
     * @throws NamingException if an exception is thrown
     * @since 1.4.0
     */
    public List<SearchResult> searchForUsername(final DirContext ctx, final String username) throws NamingException {
        LOGGER.debug("Performing a directory search for: {}", username);
        final SearchControls sc = new SearchControls();
        sc.setSearchScope(SearchControls.SUBTREE_SCOPE);
        final String searchFor = attributeName + "=" + LdapStringSanitizer.sanitize(formatPrincipal(username));
        LOGGER.debug("Searching for: {}", searchFor);
        return Collections.list(ctx.search(baseDn, searchFor, sc));
    }

    /**
     * Performs a search for the specified username. Internally, this method queries on
     * the attribute defined by {@link AlpineConfigKeys#LDAP_NAME_ATTRIBUTE}.
     *
     * @param ctx      the DirContext to use
     * @param username the username to query on
     * @return a list of SearchResult objects. If the username is found, the list should typically only contain one result.
     * @throws NamingException if an exception is thrown
     * @since 1.4.0
     */
    public SearchResult searchForSingleUsername(final DirContext ctx, final String username) throws NamingException {
        final List<SearchResult> results = searchForUsername(ctx, username);
        if (results == null || results.size() == 0) {
            LOGGER.debug("Search for ({}) did not produce any results", username);
            return null;
        } else if (results.size() == 1) {
            LOGGER.debug("Search for ({}) produced a result", username);
            return results.get(0);
        } else {
            throw new NamingException("Multiple entries in the directory contain the same username. This scenario is not supported");
        }
    }

    /**
     * Retrieves an attribute by its name for the specified dn.
     *
     * @param ctx           the DirContext to use
     * @param dn            the distinguished name of the entry to obtain the attribute value for
     * @param attributeName the name of the attribute to return
     * @return the value of the attribute, or null if not found
     * @throws NamingException if an exception is thrown
     * @since 1.4.0
     */
    public String getAttribute(final DirContext ctx, final String dn, final String attributeName) throws NamingException {
        final Attributes attributes = ctx.getAttributes(dn);
        return getAttribute(attributes, attributeName);
    }

    /**
     * Retrieves an attribute by its name for the specified search result.
     *
     * @param result        the search result of the entry to obtain the attribute value for
     * @param attributeName the name of the attribute to return
     * @return the value of the attribute, or null if not found
     * @throws NamingException if an exception is thrown
     * @since 1.4.0
     */
    public String getAttribute(final SearchResult result, final String attributeName) throws NamingException {
        return getAttribute(result.getAttributes(), attributeName);
    }

    /**
     * Retrieves an attribute by its name.
     *
     * @param attributes    the list of attributes to query on
     * @param attributeName the name of the attribute to return
     * @return the value of the attribute, or null if not found
     * @throws NamingException if an exception is thrown
     * @since 1.4.0
     */
    public String getAttribute(final Attributes attributes, final String attributeName) throws NamingException {
        if (attributes == null || attributes.size() == 0) {
            return null;
        } else {
            final Attribute attribute = attributes.get(attributeName);
            if (attribute != null) {
                final Object o = attribute.get();
                if (o instanceof String) {
                    return (String) attribute.get();
                }
            }
        }
        return null;
    }

    /**
     * Formats the principal in username@domain format or in a custom format if is specified in the config file.
     * If LDAP_USERNAME_FORMAT is configured to a non-empty value, the substring %s in this value will be replaced with the entered username.
     * The recommended format of this value depends on your LDAP server(Active Directory, OpenLDAP, etc.).
     * Examples:
     * alpine.ldap.auth.username.format=%s
     * alpine.ldap.auth.username.format=%s@company.com
     *
     * @param username the username
     * @return a formatted user principal
     * @since 1.4.0
     */
    private String formatPrincipal(final String username) {
        if (authUsernameFmt != null && !authUsernameFmt.isBlank()) {
            return String.format(authUsernameFmt, username);
        }
        return username;
    }

    private String variableSubstitution(final String s, final LdapUser user) {
        if (s == null) {
            return null;
        }
        return s.replace("{USER_DN}", LdapStringSanitizer.sanitize(user.getDN())).replace("{USERNAME}", LdapStringSanitizer.sanitize(user.getUsername()));
    }

    private String searchTermSubstitution(final String ldapFilter, String searchTerm) {
        if (ldapFilter == null) {
            return null;
        }
        if (searchTerm == null) {
            searchTerm = "";
        }
        return ldapFilter.replace("{SEARCH_TERM}", LdapStringSanitizer.sanitize(searchTerm));
    }

    /**
     * Convenience method that wraps {@link NamingEnumeration#hasMore()} but ignores {@link PartialResultException}s
     * that may be thrown as a result. This is typically an issue with a directory server that does not support
     * {@link Context#REFERRAL} being set to 'ignore' (which is the default value).
     * <p>
     * Issue: https://github.com/stevespringett/Alpine/issues/19
     *
     * @since 1.4.3
     */
    private boolean hasMoreEnum(final NamingEnumeration<SearchResult> ne) throws NamingException {
        if (ne == null) {
            return false;
        }
        boolean hasMore = true;
        try {
            if (!ne.hasMore()) {
                hasMore = false;
            }
        } catch (PartialResultException e) {
            hasMore = false;
            LOGGER.warn("Partial results returned. If this is an Active Directory server, try using port 3268 or 3269 in {}", AlpineConfigKeys.LDAP_SERVER_URL);
        }
        return hasMore;
    }

    /**
     * Closes a NamingEnumeration object without throwing any exceptions.
     *
     * @param object the NamingEnumeration object to close
     * @since 1.4.0
     */
    public void closeQuietly(final NamingEnumeration object) {
        try {
            if (object != null) {
                object.close();
            }
        } catch (final NamingException e) {
            // ignore
        }
    }

    /**
     * Closes a DirContext object without throwing any exceptions.
     *
     * @param object the DirContext object to close
     * @since 1.4.0
     */
    public void closeQuietly(final DirContext object) {
        try {
            if (object != null) {
                object.close();
            }
        } catch (final NamingException e) {
            // ignore
        }
    }

}
