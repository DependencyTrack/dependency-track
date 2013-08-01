<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN" "http://www.w3.org/TR/html4/strict.dtd">
<%@taglib uri="http://www.springframework.org/tags" prefix="spring"%>
<%@taglib uri="http://www.springframework.org/tags/form" prefix="form"%>
<%@taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<%@include file="/WEB-INF/views/templates/header.jsp" %>
<html>
<head>
<title>Dependency Track</title>
	<link href="<c:url value="/resources/style.css"/>" rel="stylesheet" type="text/css" />
    <link href="<c:url value="/resources/favicon.ico"/>" rel="shortcut icon" type="image/ico" /> 
</head>
<body>

<h2>Update Application</h2>
<a href="logout">logout</a>
<div class="content">
<form:form method="post" action="${pageContext.request.contextPath}/updateapplications/${appversionid}/${appid}">

	<table>
	<tr>
		<td><label>Application Name</label>
			<input name="name" type="text" value ="${name}" /> </td>
			
			<td><label>Application Version</label>
			<input name="version" type="text" value ="${version}"/>
			</td>
	</tr>
	
	<tr>
		<td colspan="2">
			<input type="submit" value="Update Application" />
		</td>
	</tr>
	
</table>

</form:form>

	

</div>
<%@include file="/WEB-INF/views/templates/footer.jsp" %>
</body>
</html>

