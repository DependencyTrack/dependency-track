package org.owasp.dependencytrack.service;

import org.owasp.dependencytrack.model.Roles;
import org.owasp.dependencytrack.model.User;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

/**
 * Created by Jason Wraxall on 1/12/15.
 */
public interface UserService {
    @Transactional
    void registerUser(String username, boolean isLdap, String password, Integer role);

    @Transactional
    void registerUser(String username, boolean isLdap, String password, Roles.ROLE role);

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
