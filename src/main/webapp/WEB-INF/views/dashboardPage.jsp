<%@taglib uri="http://www.springframework.org/tags" prefix="spring"%>

<spring:message code="label.dashboard" var="title"/>
<jsp:include page="/WEB-INF/views/templates/page.jsp">
    <jsp:param name="title" value="${title}"/>
    <jsp:param name="content" value="dashboard"/>
    <jsp:param name="includeVisualization" value="true"/>
</jsp:include>