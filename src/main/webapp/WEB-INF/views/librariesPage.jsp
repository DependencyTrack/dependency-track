<%@taglib uri="http://www.springframework.org/tags" prefix="spring"%>
<spring:message code="label.libraries" var="title"/>
<spring:message code="label.library.add" var="addButtonLabel"/>
<jsp:include page="/WEB-INF/views/templates/page.jsp">
    <jsp:param name="title" value="${title}"/>
    <jsp:param name="content" value="libraries"/>
    <jsp:param name="buttons" value='<a id="addLibraryModalButton" href="#libraryModal" role="button" class="open-AddLibraryModal btn" data-toggle="modal">${addButtonLabel}</a>'/>
</jsp:include>