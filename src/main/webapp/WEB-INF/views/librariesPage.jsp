<%@taglib uri="http://www.springframework.org/tags" prefix="spring"%>
<%@taglib uri="http://shiro.apache.org/tags" prefix="shiro"%>
<spring:message code="label.libraries" var="title"/>
<spring:message code="label.library.add" var="addButtonLabel"/>

<spring:message code="label.role.admin" var="admin"/>
<spring:message code="label.role.moderator" var="moderator"/>
<spring:message code="permissions.addlibraries" var="addlibraries"/>


<shiro:hasPermission  name="${addlibraries}">
<jsp:include page="/WEB-INF/views/templates/page.jsp">
    <jsp:param name="title" value="${title}"/>
    <jsp:param name="content" value="libraries"/>
    <jsp:param name="buttons" value='<a id="addLibraryModalButton" href="#libraryModal" role="button" class="open-AddLibraryModal btn" data-toggle="modal">${addButtonLabel}</a>'/>
</jsp:include>
</shiro:hasPermission>

<shiro:lacksPermission name="${addlibraries}">
    <jsp:include page="/WEB-INF/views/templates/page.jsp">
        <jsp:param name="title" value="${title}"/>
        <jsp:param name="content" value="libraries"/>
    </jsp:include>
</shiro:lacksPermission>
