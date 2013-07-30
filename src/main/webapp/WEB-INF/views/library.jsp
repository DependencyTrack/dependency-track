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

<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN" "http://www.w3.org/TR/html4/strict.dtd">
<%@taglib uri="http://www.springframework.org/tags" prefix="spring"%>
<%@taglib uri="http://www.springframework.org/tags/form" prefix="form"%>
<%@taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<%@include file="/WEB-INF/views/templates/header.jsp"%>
<html>
<head>
<title>Dependency Track</title>
<link href="<c:url value="/resources/style.css"/>" rel="stylesheet"
	type="text/css" />
<link href="<c:url value="/resources/favicon.ico"/>" rel="shortcut icon"
	type="image/ico" />
</head>
<body>

	<h2>Library List</h2>
	<a href="logout">logout</a>
	<div class="content">
		<form:form method="get"
			action="${pageContext.request.contextPath}/addlibrary/${appversionid}">

			<h2>
				<label>Add a new library to this application</label>
			</h2>
			<input name="submit" value="Add Library" type="submit" />
		</form:form>

		<h2>List of libraries</h2>
		<div>
			<c:if test="${!empty appDep}">
				<table border=3>
					<tr>
						<th>Library Name</th>
						<th>Library Version</th>
						<th>Vendor</th>
						<th>License</th>
						<th>License File</th>
						<th>Language</th>
						<th>Secunia</th>
						<th>Modify</th>
						<th>&nbsp;</th>

					</tr>
					<c:forEach items="${appDep}" var="appDep">
						<tr>
							<td>${appDep.libraryVersion.library.libraryname}</td>
							<td>${appDep.libraryVersion.libraryversion}</td>
							<td>${appDep.libraryVersion.library.libraryVendor.vendor}</td>
							<td><a href="/controller/librarylicense/${appversionid}/${appDep.libraryVersion.library.license.id}">${appDep.libraryVersion.library.license.licensename}</a></td>
							<td>${appDep.libraryVersion.library.language}</td>
							<td>${appDep.libraryVersion.library.secunia}</td>
							<td><a
								href="/controller/updatelibrary/${appversionid}/${appDep.libraryVersion.library.libraryVendor.id}/${appDep.libraryVersion.library.license.id}/${appDep.libraryVersion.library.id}
								/${appDep.libraryVersion.id}/${appDep.libraryVersion.library.libraryname}/${appDep.libraryVersion.libraryversion}/${appDep.libraryVersion.library.libraryVendor.vendor}/${appDep.libraryVersion.library.license.licensename}
								/${appDep.libraryVersion.library.language}/${appDep.libraryVersion.library.secunia}">Edit</a></td>
							<td><a href="/controller/removelibrary/${appversionid}/${appDep.libraryVersion.id}">delete</a></td>
						</tr>
					</c:forEach>

				</table>
			</c:if>
		</div>
	</div>
	<%@include file="/WEB-INF/views/templates/footer.jsp"%>
</body>
</html>