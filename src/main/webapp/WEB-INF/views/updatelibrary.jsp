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

	<h2>Update Library</h2>
	<a href="logout">logout</a>
	<div class="content">
		<form:form method="post" action="${pageContext.request.contextPath}/updatelibrary/${appversionid}/${vendorid}/${licenseid}/${libraryid}/${libraryversionid}" enctype="multipart/form-data">

			<table>
				<tr>
					<td><label>Library Name</label></td>
					<td><input name="libraryname" type="text" value="${libraryname}" /></td>

				</tr>
				<tr>
					<td><label>Library Version</label></td>
					<td><input name="libraryversion" type="text" value="${libraryversion}" /></td>

				</tr>
				<tr>
					<td><label>Vendor</label></td>
					<td><input name="vendor" type="text" value="${vendor}"/></td>

				</tr>
				<tr>
					<td><label>License</label></td>
					<td><input name="license" type="text" value="${license}"/></td>

				</tr>
				<tr>
					<td><label>License File</label></td>
					<td><input name="Licensefile" type="file" ></input></td>
				</tr>
				<tr>
					<td><label>Language</label></td>
					<td><input name="language" type="text" value="${language}"/></td>

				</tr>
				<tr>
					<td><label>SecuniaID</label></td>
					<td><input name="secuniaID" type="text" value="${secuniaID}"/></td>

				</tr>
				<tr>
					<td colspan="2"><input type="submit" value="Update" /></td>
				</tr>
			</table>
		</form:form>
		
		<form:form method="get" action="${pageContext.request.contextPath}/library/${appversionid}">
				<table>
				<tr>
    			<td> <input type="submit" value="Cancel"> </td>
				</table>    			
			</form:form>
			
	</div>
	<%@include file="/WEB-INF/views/templates/footer.jsp"%>
</body>
</html>

