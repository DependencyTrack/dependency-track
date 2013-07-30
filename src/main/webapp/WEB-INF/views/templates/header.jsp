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

<div class="pageheader">
        <div class="logo">
            <a href="${pageContext.request.contextPath}"><img  src="<c:url value="${pageContext.request.contextPath}/resources/images/corner.png"/>" width="104" height="48" alt="OWASP Logo"/></a>
        </div>
        <span id="name">${properties.longname}</span>
    </div>