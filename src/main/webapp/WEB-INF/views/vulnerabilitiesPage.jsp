<%@taglib uri="http://www.springframework.org/tags" prefix="spring"%>
<%@taglib uri="http://www.springframework.org/tags/form" prefix="form"%>
<%@taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<%@taglib uri="http://java.sun.com/jsp/jstl/functions" prefix="fn"%>

<spring:message code="label.application" var="applicationLabel"/>
<spring:message code="label.vulnerabilities" var="vulnerabilities"/>

<jsp:include page="/WEB-INF/views/templates/page.jsp">
    <jsp:param name="title" value="${applicationVersion.application.name} - ${applicationVersion.version} - ${vulnerabilities}"/>

    <jsp:param name="buttons" value='<div class="btn-group">
             <a id="backButton" href="../applicationVersion/${applicationVersion.id}" class="btn">${applicationLabel}</a>
             <a id="htmlButton" href="../dependencyCheckReport/${applicationVersion.id}.html" class="btn">HTML</a>
             <a id="xmlButton" href="../dependencyCheckReport/${applicationVersion.id}.xml" class="btn">XML</a>
             </div>'/>

    <jsp:param name="content" value="vulnerabilities"/>
</jsp:include>