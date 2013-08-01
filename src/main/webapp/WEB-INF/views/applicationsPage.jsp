<%@taglib uri="http://www.springframework.org/tags" prefix="spring"%>
<spring:message code="label.applications" var="title"/>
<spring:message code="label.application.add" var="buttonLabel"/>
<jsp:include page="/WEB-INF/views/templates/page.jsp">
    <jsp:param name="title" value="${title}"/>
    <jsp:param name="buttons" value='<a id="addApplicationModalButton" href="#applicationModal" role="button" class="btn" data-toggle="modal">${buttonLabel}</a>'/>
    <jsp:param name="content" value="applications"/>
</jsp:include>