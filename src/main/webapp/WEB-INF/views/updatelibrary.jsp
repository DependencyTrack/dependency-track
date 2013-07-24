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

