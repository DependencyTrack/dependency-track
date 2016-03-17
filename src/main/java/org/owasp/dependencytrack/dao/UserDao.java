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
package org.owasp.dependencytrack.dao;

import org.owasp.dependencytrack.model.Roles;
import org.owasp.dependencytrack.model.User;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

/**
 * Created by Jason Wraxall on 1/12/15.
 */
public interface UserDao {

    @Transactional
    void registerUser(String username, boolean isLdap, String password, Integer role);

    @Transactional
    List<User> accountManagement();

    @Transactional
    void validateuser(int userid);

    @Transactional
    void deleteUser(int userid);

    @Transactional
    List<Roles> getRoleList();

    @Transactional
    void changeUserRole(int userid, int role);

    @Transactional
    boolean confirmUserPassword(String username, String password);

    @Transactional
    boolean changePassword(String username, String password);

    @Transactional
    boolean isLdapUser(String username);
}
