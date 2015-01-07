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
 *
 * Copyright (c) Axway. All Rights Reserved.
 */
package org.owasp.dependencytrack.controller;

import org.apache.commons.io.IOUtils;
import org.apache.shiro.authz.annotation.RequiresPermissions;
import org.owasp.dependencytrack.service.UserService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.Map;
import java.util.Properties;

/**
 * Controller logic for all user management related requests.
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
     * Admin User Management change scan schedule.
     */
    @RequiresPermissions("usermanagement")
    @RequestMapping(value = "/changescanschedule/{numberOfDays}", method = RequestMethod.GET)
    public String changeScanSchedule(@PathVariable("numberOfDays") String numberOfDays) {
        OutputStream output = null;
        try {
            final Properties prop = new Properties();
            output = new FileOutputStream("application.properties");
            // set the properties value
            prop.setProperty("scanschedule", numberOfDays);
            // save properties to project root folder
            prop.store(output, null);
            output.close();
        } catch (IOException e) {
            LOGGER.error("An error occurred while changing Dependency-Check scan schedule");
            LOGGER.error(e.getMessage());
        } finally {
            IOUtils.closeQuietly(output);
        }

        return "userManagementPage";
    }

    /**
     * Admin User Management which validates a user.
     */
    @RequiresPermissions("validateuser")
    @RequestMapping(value = "/validateuser/{id}", method = RequestMethod.GET)
    public String validateUser(@PathVariable("id") Integer userid) {
        userService.validateuser(userid);
        return "userManagementPage";
    }

    /**
     * Admin User Management which deletes a user.
     */
    @RequiresPermissions("deleteuser")
    @RequestMapping(value = "/deleteuser/{id}", method = RequestMethod.GET)
    public String deleteUser(@PathVariable("id") Integer userid) {
        userService.deleteUser(userid);
        return "userManagementPage";
    }

    /**
     * Admin User Management which deletes a user.
     */
    @RequiresPermissions("changeuserrole")
    @RequestMapping(value = "/changeuserrole/{id}/{role}", method = RequestMethod.GET)
    public String changeUserRole(@PathVariable("id") Integer userid, @PathVariable("role") Integer role) {
        userService.changeUserRole(userid, role);
        return "userManagementPage";
    }

}
