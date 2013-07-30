<%@taglib uri="http://www.springframework.org/tags" prefix="spring"%>
<%@taglib uri="http://www.springframework.org/tags/form" prefix="form"%>
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

<form:form method="post" action="${pageContext.request.contextPath}/addlibrary/${appversionid}">
                    <table>
                        <tr>
                            <td><label for="libraryname">Library Name</label></td>
                            <td><input id="libraryname" name="libraryname" type="text" /></td>

                        </tr>
                        <tr>
                            <td><label for="libraryversion">Library Version</label></td>
                            <td><input id="libraryversion" name="libraryversion" type="text" /></td>

                        </tr>
                        <tr>
                            <td><label for="vendor">Vendor</label></td>
                            <td><input id="vendor" name="vendor" type="text" /></td>

                        </tr>
                        <tr>
                            <td><label for="license">License</label></td>
                            <td><input id="license" name="license" type="text" /></td>

                        </tr>
                        <tr>
                            <td><label for="Licensefile">License File</label></td>
                            <td><input id="Licensefile" name="Licensefile" type="file" /></td>

                        </tr>

                        <tr>
                            <td><label for="language">Language</label></td>
                            <td><input id="language" name="language" type="text" /></td>

                        </tr>
                        <tr>
                            <td><label for="secuniaID">SecuniaID</label></td>
                            <td><input id="secuniaID" name="secuniaID" type="text" /></td>

                        </tr>
                        <tr>
                            <td></td>
                            <td>
                                <input type="submit" value="Add" />
                                <input type="button" value="Cancel" onclick="window.location='/library/${appversionid}'" />
                            </td>
                        </tr>
                    </table>
                </form:form>