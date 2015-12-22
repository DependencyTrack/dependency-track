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
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.subject.Subject;
import org.owasp.dependencytrack.service.UserService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.util.Map;

/**
 * Controller logic for all Login-related requests.
 *
 * @author Steve Springett (steve.springett@owasp.org)
 */
@Controller
public class LoginController extends AbstractController {

    /**
     * Setup logger
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(LoginController.class);

    /**
     * The Dependency-Track UserService.
     */
    @Autowired
    private UserService userService;

    /**
     * Login action.
     *
     * @param request  a HttpServletRequest object
     * @param map      Map
     * @param username The username to login with
     * @param password The password to login with
     * @return A String
     */
    @RequestMapping(value = "/login", method = RequestMethod.POST)
    public String loginCheck(HttpServletRequest request,
                             Map<String, Object> map,
                             @RequestParam("username") String username,
                             @RequestParam("password") String password) {

        setLdapStatus(request, false);
        final UsernamePasswordToken token = new UsernamePasswordToken(username, password);
        try {
            SecurityUtils.getSubject().login(token);

            LOGGER.info("Login successful: " + username);
            if (SecurityUtils.getSubject().isAuthenticated()) {
                setLdapStatus(request, userService.isLdapUser(username));
                return "redirect:/dashboard";
            }
        } catch (AuthenticationException e) {
            LOGGER.info("Login failure: " + username);
            map.put("authenticationException", true);
        }
        return "loginPage";
    }

    /**
     * Login action.
     *
     * @param request a HttpServletRequest object
     * @param response a HttpServletResponse object
     * @return a String
     */
    @RequestMapping(value = "/login", method = {RequestMethod.GET, RequestMethod.HEAD})
    public String login(HttpServletRequest request, HttpServletResponse response) {
        setLdapStatus(request, false);
        response.addCookie(new Cookie("CONTEXTPATH", getServletContext().getContextPath()));
        final String s = "loginPage";
        if (SecurityUtils.getSubject().isAuthenticated()) {
            return "redirect:/dashboard";
        }
        return s;
    }

    /**
     * Logout action.
     *
     * @param request a HttpServletRequest object
     * @return a String
     */
    @RequestMapping(value = "/logout", method = RequestMethod.GET)
    public String logout(HttpServletRequest request) {
        setLdapStatus(request, false);
        final Subject subject = SecurityUtils.getSubject();
        LOGGER.info("Logout: " + subject.getPrincipal());
        subject.logout();
        return "redirect:/login";
    }

    /**
     * Writes (to a session attribute) whether the user was authenticated via LDAP or not.
     * @param request a HttpServletRequest object
     * @param isLdap a boolean indicating ldap authentication
     */
    private void setLdapStatus(HttpServletRequest request, boolean isLdap) {
        final HttpSession session = request.getSession();
        if (session != null) {
            session.setAttribute("isLdap", isLdap);
        }
    }
}
