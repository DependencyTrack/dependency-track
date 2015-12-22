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
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authc.credential.SimpleCredentialsMatcher;
import org.mindrot.jbcrypt.BCrypt;

/**
 * An Apache Shiro {@link org.apache.shiro.authc.credential.CredentialsMatcher CredentialsMatcher}
 * implementation that supports BCrypt.
 *
 * @author Steve Springett (steve.springett@owasp.org)
 */
public class BcryptCredentialsMatcher extends SimpleCredentialsMatcher {

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean doCredentialsMatch(AuthenticationToken token, AuthenticationInfo info) {
        final UsernamePasswordToken upToken = (UsernamePasswordToken) token;
        String storedBcryptPassword;
        if (info.getCredentials() instanceof char[]) {
            storedBcryptPassword = new String((char[]) info.getCredentials());
        } else {
            storedBcryptPassword = info.getCredentials().toString();
        }
        final String assertedPlaintextPassword = new String(upToken.getPassword());
        return BCrypt.checkpw(assertedPlaintextPassword, storedBcryptPassword);
    }

}
