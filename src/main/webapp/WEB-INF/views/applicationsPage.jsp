<%@taglib uri="http://www.springframework.org/tags" prefix="spring"%>
<spring:message code="navbar.applications" var="title"/>
<jsp:include page="/WEB-INF/views/templates/page.jsp">
    <jsp:param name="title" value="Applications"/>
    <jsp:param name="buttons" value='<a id="addApplicationModalButton" href="#applicationModal" role="button" class="btn" data-toggle="modal">Add Application</a>'/>
    <jsp:param name="content" value="applications"/>
</jsp:include>