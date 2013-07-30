<%@taglib uri="http://www.atg.com/taglibs/json" prefix="json" %>
<%@taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<%--
  ~ Copyright 2013 Axway
  ~
  ~ This file is part of OWASP Dependency-Track.
  ~
  ~ Dependency-Track is free software: you can redistribute it and/or modify it under the terms of the
  ~ GNU General Public License as published by the Free Software Foundation, either version 3 of the
  ~ License, or (at your option) any later version.
  ~
  ~ Dependency-Track is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
  ~ even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General
  ~ Public License for more details.
  ~
  ~ You should have received a copy of the GNU General Public License along with Dependency-Track.
  ~ If not, see http://www.gnu.org/licenses/.
  --%>

<c:set var="atg.taglib.json.prettyPrint" value="${true}" scope="application"/>

<json:object>
    <json:array name="vendors" var="vendor" items="${libraryVendors}">
        <json:object>
            <json:property name="id" value="${vendor.id}"/>
            <json:property name="vendor" value="${vendor.vendor}"/>

            <json:array name="libraries" var="library" items="${vendor.libraries}">
                <json:object>
                    <json:property name="id" value="${library.id}"/>
                    <json:property name="name" value="${library.libraryname}"/>
                    <json:property name="license" value="${library.license}"/>
                    <json:property name="language" value="${library.language}"/>

                    <json:array name="versions" var="version" items="${library.versions}">
                        <json:object>
                            <json:property name="id" value="${version.id}"/>
                            <json:property name="version" value="${version.libraryversion}"/>
                        </json:object>
                    </json:array>

                </json:object>
            </json:array>

        </json:object>
    </json:array>
</json:object>