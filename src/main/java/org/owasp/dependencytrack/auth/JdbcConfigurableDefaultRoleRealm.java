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

import org.apache.shiro.realm.jdbc.JdbcRealm;
import org.owasp.dependencytrack.model.Roles;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.sql.Connection;
import java.sql.SQLException;
import java.util.Set;

/**
 * Custom Shiro JdbcRealm implementation that provides the ability to have
 * a configurable default role if a role is not assigned to a user.
 *
 * @author Steve Springett (steve.springett@owasp.org)
 */
@Component
public class JdbcConfigurableDefaultRoleRealm extends JdbcRealm {

    @Value("${defaultUserRole:USER}")
    public String userRole;

    private Roles.ROLE defaultUserRole() {
        return Roles.ROLE.getRole(userRole);
    }

    /**
     * {@inheritDoc}
     */
    protected Set<String> getRoleNamesForUser(Connection conn, String username) throws SQLException {
        final Set<String> roleNames = super.getRoleNamesForUser(conn, username);

        final Roles.ROLE defaultRole = defaultUserRole();
        if (roleNames.size() == 0 && defaultRole != null) {
            roleNames.add(defaultRole.name().toLowerCase());
        }

        return roleNames;
    }

}
