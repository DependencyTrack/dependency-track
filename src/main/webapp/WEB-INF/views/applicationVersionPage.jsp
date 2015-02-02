<%@taglib uri="http://www.springframework.org/tags" prefix="spring"%>
<%@taglib uri="http://www.springframework.org/tags/form" prefix="form"%>
<%@taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<%@taglib uri="http://java.sun.com/jsp/jstl/functions" prefix="fn"%>
<%@taglib uri="http://shiro.apache.org/tags" prefix="shiro"%>

<spring:message code="label.dependency.add" var="addDependencyLabel"/>
<spring:message code="label.clone" var="cloneLabel"/>
<spring:message code="label.edit" var="editLabel"/>
<spring:message code="label.vulnerabilities" var="vulnerabilitiesLabel"/>

<spring:message code="label.role.admin" var="admin"/>
<spring:message code="label.role.moderator" var="moderator"/>
<spring:message code="permissions.addDependency" var="addDependency"/>
<spring:message code="permissions.vulnerabilities" var="vulnerabilities"/>

<shiro:hasPermission name="${addDependency}">
<jsp:include page="/WEB-INF/views/templates/page.jsp">
    <jsp:param name="title" value="${applicationVersion.application.name} - ${applicationVersion.version}"/>
             <jsp:param name="buttons" value='<div class="btn-group">
             <a id="addDependencyModalButton" href="#addDependencyModal" role="button" class="btn" data-toggle="modal">${addDependencyLabel}</a>
             <a id="cloneVersionModalButton" href="#cloneVersionModal" role="button" class="open-CloneApplicationVersionModal btn" data-toggle="modal" data-id="${applicationVersion.application.id}" data-version="${applicationVersion.version}">${cloneLabel}</a>
             <a id="editDependencyModalButton" href="#editDependencyModal" class="open-EditDependencyModal btn" role="button" class="btn" data-id="${applicationVersion.id}" data-ver="${applicationVersion.version}" data-toggle="modal">${editLabel}</a>
             <a id="vulnerabilitiesButton" href="../vulnerabilities/${applicationVersion.id}" class="btn">${vulnerabilitiesLabel}</a>
             </div>'/>
    <jsp:param name="content" value="applicationVersion"/>
</jsp:include>
</shiro:hasPermission>

<shiro:hasPermission name="${vulnerabilities}">
    <shiro:lacksPermission name="${addDependency}">
        <jsp:include page="/WEB-INF/views/templates/page.jsp">
            <jsp:param name="title" value="${applicationVersion.application.name} - ${applicationVersion.version}"/>
            <jsp:param name="buttons" value='<div class="btn-group">
             <a id="vulnerabilitiesButton" href="../vulnerabilities/${applicationVersion.id}" class="btn">${vulnerabilitiesLabel}</a>
             </div>'/>
            <jsp:param name="content" value="applicationVersion"/>
        </jsp:include>
    </shiro:lacksPermission>
</shiro:hasPermission>

<shiro:lacksPermission name="${addDependency}">
    <jsp:include page="/WEB-INF/views/templates/page.jsp">
        <jsp:param name="title" value="${applicationVersion.application.name} - ${applicationVersion.version}"/>
        <jsp:param name="content" value="applicationVersion"/>
</jsp:include>
</shiro:lacksPermission>