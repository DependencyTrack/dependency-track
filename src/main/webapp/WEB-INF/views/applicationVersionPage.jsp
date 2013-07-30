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

<jsp:include page="/WEB-INF/views/templates/page.jsp">
    <jsp:param name="title" value="${applicationVersion.application.name} - ${applicationVersion.version}"/>

             <jsp:param name="buttons" value='<div class="btn-group">
             <a id="addDependencyModalButton" href="#addDependencyModal" role="button" class="btn" data-toggle="modal">Add Dependency</a>
             <a id="cloneVersionModalButton" href="#cloneVersionModal" role="button" class="open-CloneApplicationVersionModal btn" data-toggle="modal" data-id="${applicationVersion.application.id}" data-version="${applicationVersion.version}">Clone</a>
             <a id="editDependencyModalButton" href="#editDependencyModal" class="open-EditDependencyModal btn" role="button" class="btn" data-id="${applicationVersion.id}" data-ver="${applicationVersion.version}" data-toggle="modal">Edit</a>
             </div>'/>

    <jsp:param name="content" value="applicationVersion"/>
</jsp:include>

