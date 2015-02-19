<%@taglib uri="http://www.springframework.org/tags" prefix="spring"%>
<spring:message code="label.user.management" var="title"/>
<spring:message code="label.userManagementTitle.addUser" var="addUserButtonLabel"/>
<jsp:include page="/WEB-INF/views/templates/page.jsp">
    <jsp:param name="title" value="${title}"/>
    <jsp:param name="content" value="usermanagement"/>
    <jsp:param name="buttons" value='<a id="addUserModalButton" data-toggle="modal" role="button" class="btn" href="#registerUserModal">${addUserButtonLabel}</a>'/>
</jsp:include>