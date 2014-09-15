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

package org.owasp.dependencytrack.controller.token;

import org.springframework.web.servlet.support.RequestDataValueProcessor;

import javax.servlet.http.HttpServletRequest;
import java.util.HashMap;
import java.util.Map;


public class TokenRequestDataValueProcessor implements RequestDataValueProcessor {

    /**
     * Adds a hidden field to every Spring form (&lt;form:form&gt;) containing the token value to use for the
     * next POST operation.
     * @param request a HttpServletRequest object
     * @return a Map of hidden fields
     */
    public Map<String, String> getExtraHiddenFields(HttpServletRequest request) {
        final Map<String, String> hiddenFields = new HashMap<>();
        hiddenFields.put(TokenManager.TOKEN_PARAM_NAME, TokenManager.getToken(request.getSession()));
        return hiddenFields;
    }

    /**
     * Invoked when a new form action is rendered. Not required for token logic. Required by interface.
     * @param request the current request
     * @param action the form action
     * @return the action to use, possibly modified
     */
    public String processAction(HttpServletRequest request, String action) {
        return action;
    }

    /**
     * Invoked when a form field value is rendered. Not required for token logic. Required by interface.
     * @param request the current request
     * @param name the form field name
     * @param value the form field value
     * @param type the form field type ("text", "hidden", etc.)
     * @return the form field value to use, possibly modified
     */
    public String processFormFieldValue(HttpServletRequest request, String name, String value, String type) {
        return value;
    }

    /**
     * Invoked when a URL is about to be rendered or redirected to. Not required for token logic. Required by interface.
     * @param request the current request
     * @param url the URL value
     * @return the URL to use, possibly modified
     */
    public String processUrl(HttpServletRequest request, String url) {
        return url;
    }

}
