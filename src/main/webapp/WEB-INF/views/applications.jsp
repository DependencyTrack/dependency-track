<%@taglib uri="http://www.springframework.org/tags" prefix="spring"%>
<%@taglib uri="http://www.springframework.org/tags/form" prefix="form"%>
<%@taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<%@taglib uri="http://java.sun.com/jsp/jstl/functions" prefix="fn"%>

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

<div id="applicationContainer">
    <c:if test="${!empty applicationList}">

        <table id="applicationTable" class="list">
            <tr>
                <th></th>
                <th>Name</th>
                <th>Versions</th>
                <th></th>
            </tr>
            <c:forEach items="${applicationList}" var="application">
                <tr>
                    <td id="applicationCaret>${application.id}" data-toggle="collapse" data-target="#applicationDetails${application.id}" style="vertical-align:top;width:20px;height:20px;"><span class="caret"></span></td>
                    <td style="vertical-align:top;"><a href="javascript:void(0);" data-toggle="collapse" data-target="#applicationDetails${application.id}">${application.name}</a>
                        <div id="applicationDetails${application.id}" class="collapse">
                            <ul class="nav nav-list">
                                <li class="nav-header">Versions of ${application.name}</li>
                            <c:forEach items="${application.versions}" var="version">
                                <li><a href="applicationVersion/${version.id}">${version.version}</a></li>
                            </c:forEach>
                            </ul>
                        </div>
                    </td>
                    <td style="vertical-align:top;">${fn:length(application.versions)}</td>
                    <td style="vertical-align:top;text-align:right;">
                        <div class="btn-group">
                            <a data-toggle="modal" data-id="${application.id}" class="open-CloneApplicationModal btn" href="#cloneApplicationModal">Clone Application</a>
                            <a data-toggle="modal" data-id="${application.id}" class="open-AddApplicationVersionModal btn" href="#addApplicationVersionModal">Add Version</a>
                            <a data-toggle="modal" data-id="${application.id}" data-name="${application.name}" class="open-EditApplicationModal btn" href="#editApplicationModal">Edit</a>
                        </div>
                    </td>
                </tr>


            </c:forEach>
        </table>
    </c:if>
</div>

<div id="applicationModal" class="modal hide fade" tabindex="-1" role="dialog" aria-labelledby="applicationModalLabel" aria-hidden="true">
    <div class="modal-header">
        <h4 id="applicationModalLabel">New Application</h4>
    </div>
    <form:form id="addApplicationForm" style="margin-bottom:0" action="${pageContext.request.contextPath}/addApplication" method="post" autocomplete="off">
        <div class="modal-body">
            <table>
                <tr>
                    <td><label for="name">Name</label></td>
                    <td><input id="name" name="name" type="text" autofocus="autofocus" required="required"/></td>
                </tr>
                <tr>
                    <td><label for="version">Version</label></td>
                    <td><input id="version" name="version" type="text" required="required"/></td>
                </tr>
            </table>
        </div>
        <div class="modal-footer">
            <button class="btn" data-dismiss="modal" aria-hidden="true">Close</button>
            <button class="modalSubmit btn btn-primary">Add Application</button>
        </div>
    </form:form>
</div>

<div id="editApplicationModal" class="modal hide fade" tabindex="-1" role="dialog" aria-labelledby="editApplicationModalLabel" aria-hidden="true">
    <div class="modal-header">
        <h4 id="editApplicationModalLabel">Edit Application
            <span class="delete-span">
				<a class="btn btn-danger header-button" id="deleteLink" href="" onclick="return confirm('Are you sure you want to delete the application?')">Delete</a>
			</span>
        </h4>
    </div>
    <form:form id="editApplicationForm" style="margin-bottom:0" action="${pageContext.request.contextPath}/updateApplication" method="post" autocomplete="off">
        <div class="modal-body">
            <table>
                <tr>
                    <td><label for="editname">Name</label></td>
                    <td><input id="editname" name="name" type="text" autofocus="autofocus" required="required" value=""/></td>
                </tr>
            </table>
            <input type="hidden" id="editid" name="id" value=""/>
        </div>
        <div class="modal-footer">
            <button class="btn" data-dismiss="modal" aria-hidden="true">Close</button>
            <button class="modalSubmit btn btn-primary">Save Changes</button>
        </div>
    </form:form>
</div>

<div id="addApplicationVersionModal" class="modal hide fade" tabindex="-1" role="dialog" aria-labelledby="addApplicationVersionModalLabel" aria-hidden="true">
    <div class="modal-header">
        <h4 id="addApplicationVersionModalLabel">Add Version</h4>
    </div>
    <form:form id="addApplicationVersionForm" style="margin-bottom:0" action="${pageContext.request.contextPath}/addApplicationVersion" method="post" autocomplete="off">
        <div class="modal-body">
            <table>
                <tr>
                    <td><label for="addversion">Version</label></td>
                    <td><input id="addversion" name="version" type="text" autofocus="autofocus" required="required" value=""/></td>
                </tr>
            </table>
            <input type="hidden" id="addid" name="id" value=""/>
        </div>
        <div class="modal-footer">
            <button class="btn" data-dismiss="modal" aria-hidden="true">Close</button>
            <button class="modalSubmit btn btn-primary">Add Version</button>
        </div>
    </form:form>
</div>

<div id="cloneApplicationModal" class="modal hide fade" tabindex="-1" role="dialog" aria-labelledby="cloneApplicationModalLabel" aria-hidden="true">
    <div class="modal-header">
        <h4 id="cloneApplicationModalLabel">Enter New Application Name</h4>
    </div>
    <%--add link to controller--%>
    <form:form id="cloneApplicationForm" style="margin-bottom:0" action="${pageContext.request.contextPath}/cloneApplication" method="post" autocomplete="off">
        <div class="modal-body">
            <table>
                <tr>
                    <td><label for="cloneAppName">Name</label></td>
                    <td><input id="cloneAppName" name="cloneAppName" type="text" autofocus="autofocus" required="required"/></td>
                </tr>
            </table>
            <input type="hidden" id="applicationid" name="applicationid" value=""/>
        </div>
        <div class="modal-footer">
            <button class="btn" data-dismiss="modal" aria-hidden="true">Close</button>
            <button class="modalSubmit btn btn-primary">Clone</button>
        </div>
    </form:form>
</div>