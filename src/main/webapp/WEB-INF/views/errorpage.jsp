<%@taglib uri="http://www.springframework.org/tags" prefix="spring"%>
<%@ taglib prefix="shiro" uri="http://shiro.apache.org/tags" %>
<spring:message code="label.errorTitle" var="title"/>
<shiro:authenticated>
<jsp:include page="/WEB-INF/views/templates/page.jsp">
    <jsp:param name="title" value="${title}"/>
    <jsp:param name="content" value="error"/>
</jsp:include>
</shiro:authenticated>