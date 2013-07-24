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

	<h2>License List</h2>
	<a href="logout">logout</a>
	<div class="content">
		
		<h2>License for library</h2>
		<div>
			<c:if test="${!empty licenseList}">
				<table border=3>
					<tr>
						<th>License</th>
						<th>License File</th>


					</tr>
					<c:forEach items="${licenseList}" var="list">
						<tr>
							<td>${list.licensename}</td>
							<td><a href="/controller/downloadlicense/${appversionid}/${list.id}">Download</a></td>
	
						</tr>
					</c:forEach>

				</table>
			</c:if>
		</div>
	</div>
	<%@include file="/WEB-INF/views/templates/footer.jsp"%>
</body>
</html>

