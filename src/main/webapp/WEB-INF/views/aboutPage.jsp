<%@taglib uri="http://www.springframework.org/tags" prefix="spring"%>
<spring:message code="label.aboutTitle" var="title"/>
<jsp:include page="/WEB-INF/views/templates/page.jsp">
    <jsp:param name="title" value="${title}"/>
    <jsp:param name="content" value="about"/>
</jsp:include>