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
package org.owasp.dependencytrack.controller;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authz.annotation.RequiresPermissions;
import org.apache.shiro.subject.Subject;
import org.owasp.dependencytrack.service.UserService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;

import java.util.Map;

/**
 * Controller logic for all user management related requests.
 *
 * @author Steve Springett (steve.springett@owasp.org)
 */
@Controller
public class UserManagementController extends AbstractController {

    /**
     * Setup logger
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(UserManagementController.class);

    /**
     * The Dependency-Track UserService.
     */
    @Autowired
    private UserService userService;


    /**
     * Admin User Management.
     */
    @RequiresPermissions("usermanagement")
    @RequestMapping(value = "/usermanagement", method = RequestMethod.GET)
    public String userManagement(Map<String, Object> map) {
        map.put("userList", userService.accountManagement());
        map.put("roleList", userService.getRoleList());
        return "userManagementPage";
    }

    /**
     * Admin User Management which validates a user.
     */
    @RequiresPermissions("validateuser")
    @RequestMapping(value = "/usermanagement/validateuser/{id}", method = RequestMethod.GET)
    public String validateUser(@PathVariable("id") Integer userid) {
        userService.validateuser(userid);
        return "userManagementPage";
    }

    /**
     * Admin User Management which deletes a user.
     */
    @RequiresPermissions("deleteuser")
    @RequestMapping(value = "/usermanagement/deleteuser/{id}", method = RequestMethod.GET)
    public String deleteUser(@PathVariable("id") Integer userid) {
        userService.deleteUser(userid);
        return "userManagementPage";
    }

    /**
     * Admin User Management which deletes a user.
     */
    @RequiresPermissions("changeuserrole")
    @RequestMapping(value = "/usermanagement/changeuserrole/{id}/{role}", method = RequestMethod.GET)
    public String changeUserRole(@PathVariable("id") Integer userid, @PathVariable("role") Integer role) {
        userService.changeUserRole(userid, role);
        return "userManagementPage";
    }

    /**
     * Changes the current users password
     * @param currentPassword the users existing password
     * @param newPassword the users new password
     * @param confirm the confirmation of the new password
     */
    @RequestMapping(value = "/changepassword", method = RequestMethod.POST)
    public String registerUser(@RequestParam("currentpassword") String currentPassword,
                               @RequestParam("newpassword") String newPassword,
                               @RequestParam("confirm") String confirm) {

        final Subject subject = SecurityUtils.getSubject();
        final String username = (String) SecurityUtils.getSubject().getPrincipal();
        if (!userService.confirmUserPassword(username, currentPassword)) {
            LOGGER.info("Subject password change failure: " + username);
            subject.logout();
            return "redirect:/login";
        }

        if (newPassword != null && confirm != null && newPassword.equals(confirm)) {
            final boolean changed = userService.changePassword(username, newPassword);
            if (changed) {
                LOGGER.info("Subject changed password: " + username);
                subject.logout();
                return "redirect:/login";
            }
        }
        return "redirect:/dashboard";
    }

    /**
     * Adds a new user to the system
     * @param username the username of the user
     * @param isLdap is the username local or an ldap user
     * @param password the users password
     * @param chkpassword a confirmation of the users password
     * @param role the role id for the user
     */
    @RequiresPermissions("usermanagement")
    @RequestMapping(value = "/usermanagement/registerUser", method = RequestMethod.POST)
    public String registerUser(@RequestParam("username") String username,
                               @RequestParam(required = false, value = "isldap") String isLdap,
                               @RequestParam(required = false, value = "password") String password,
                               @RequestParam(required = false, value = "chkpassword") String chkpassword,
                               @RequestParam("role") Integer role) {
        if (isLdap == null && password != null && chkpassword != null && password.equals(chkpassword)) {
            userService.registerUser(username, false, password, role);
        } else if (isLdap != null){
            userService.registerUser(username, true, null, role);
        }
        return "redirect:/usermanagement";
    }
}
