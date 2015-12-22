/*
 * This file is part of Dependency-Track.
 *
 * Dependency-Track is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option) any
 * later version.
 *
 * Dependency-Track is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * Dependency-Track. If not, see http://www.gnu.org/licenses/.
 */
package org.owasp.dependencytrack.auth;

import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.ldap.AbstractLdapRealm;
import org.apache.shiro.realm.ldap.LdapContextFactory;
import org.apache.shiro.realm.ldap.LdapUtils;
import org.apache.shiro.subject.PrincipalCollection;

import javax.naming.NamingException;
import javax.naming.ldap.LdapContext;

/**
 * A {@link org.apache.shiro.realm.Realm} that authenticates with an active directory LDAP
 * server. This implementation only authenticates via Active Directory. No authorization
 * checks (roles and permissions) are made by this class. This class is intended to be used
 * in conjunction with {@link org.apache.shiro.realm.jdbc.JdbcRealm} to provide authentication
 * via LDAP and control over roles and permissions locally.
 *
 * @author Steve Springett (steve.springett@owasp.org)
 */
public class ActiveDirectoryAuthenticationRealm extends AbstractLdapRealm {


    /**
     * Builds an {@link org.apache.shiro.authc.AuthenticationInfo} object by querying the active directory LDAP context for the
     * specified username.  This method binds to the LDAP server using the provided username and password -
     * which if successful, indicates that the password is correct.
     * <p/>
     *
     * @param token              the authentication token provided by the user.
     * @param ldapContextFactory the factory used to build connections to the LDAP server.
     * @return an {@link org.apache.shiro.authc.AuthenticationInfo} instance containing information retrieved from LDAP.
     * @throws javax.naming.NamingException if any LDAP errors occur during the search.
     */
    protected AuthenticationInfo queryForAuthenticationInfo(AuthenticationToken token, LdapContextFactory ldapContextFactory) throws NamingException {
        final UsernamePasswordToken upToken = (UsernamePasswordToken) token;
        LdapContext ctx = null;
        try {
            ctx = ldapContextFactory.getLdapContext(upToken.getUsername(), String.valueOf(upToken.getPassword()));
        } finally {
            LdapUtils.closeContext(ctx);
        }
        return new SimpleAuthenticationInfo(upToken.getUsername(), upToken.getPassword(), getName());
    }


    /**
     * Builds an empty {@link org.apache.shiro.authz.AuthorizationInfo} object without any roles.
     *
     * @param principals         the principal of the Subject whose account is being retrieved.
     * @param ldapContextFactory the factory used to create LDAP connections.
     * @return the AuthorizationInfo for the given Subject principal.
     * @throws NamingException if an error occurs when searching the LDAP server.
     */
    protected AuthorizationInfo queryForAuthorizationInfo(PrincipalCollection principals, LdapContextFactory ldapContextFactory) throws NamingException {
        return new SimpleAuthorizationInfo();
    }
}
