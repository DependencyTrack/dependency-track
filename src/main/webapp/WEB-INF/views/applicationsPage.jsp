<%@taglib uri="http://www.springframework.org/tags" prefix="spring"%>
<%@taglib uri="http://shiro.apache.org/tags" prefix="shiro"%>
<spring:message code="label.applications" var="title"/>
<spring:message code="label.application.add" var="buttonLabel"/>

<spring:message code="permissions.addApplication" var="addApplication"/>
<spring:message code="label.role.moderator" var="moderator"/>
<spring:message code="label.role.user" var="user"/>

<shiro:hasPermission name="${addApplication}">

<jsp:include page="/WEB-INF/views/templates/page.jsp">
    <jsp:param name="title" value="${title}"/>
    <jsp:param name="buttons" value='<a id="addApplicationModalButton" href="#applicationModal" role="button" class="btn" data-toggle="modal">${buttonLabel}</a>'/>
    <jsp:param name="content" value="applications"/>
</jsp:include>

</shiro:hasPermission>

<shiro:lacksPermission name="${addApplication}">
<jsp:include page="/WEB-INF/views/templates/page.jsp">
    <jsp:param name="title" value="${title}"/>

    <jsp:param name="content" value="applications"/>
</jsp:include>
    </shiro:lacksPermission>
