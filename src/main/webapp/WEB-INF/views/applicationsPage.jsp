<%@taglib uri="http://www.springframework.org/tags" prefix="spring"%>
<%@ taglib prefix="shiro" uri="http://shiro.apache.org/tags" %>
<spring:message code="label.applications" var="title"/>
<spring:message code="label.application.add" var="buttonLabel"/>

<spring:message code="label.role.admin" var="admin"/>
<spring:message code="label.role.moderator" var="moderator"/>
<spring:message code="label.role.user" var="user"/>

<shiro:hasAnyRoles name="${admin},${moderator}">

<jsp:include page="/WEB-INF/views/templates/page.jsp">
    <jsp:param name="title" value="${title}"/>
    <jsp:param name="buttons" value='<a id="addApplicationModalButton" href="#applicationModal" role="button" class="btn" data-toggle="modal">${buttonLabel}</a>'/>
    <jsp:param name="content" value="applications"/>
</jsp:include>

</shiro:hasAnyRoles>

<shiro:hasRole name="${user}">
<jsp:include page="/WEB-INF/views/templates/page.jsp">
    <jsp:param name="title" value="${title}"/>

    <jsp:param name="content" value="applications"/>
</jsp:include>
    </shiro:hasRole>
