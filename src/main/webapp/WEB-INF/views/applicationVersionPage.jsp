<%@taglib uri="http://www.springframework.org/tags" prefix="spring"%>
<%@taglib uri="http://www.springframework.org/tags/form" prefix="form"%>
<%@taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<%@taglib uri="http://java.sun.com/jsp/jstl/functions" prefix="fn"%>

<jsp:include page="/WEB-INF/views/templates/page.jsp">
    <jsp:param name="title" value="${applicationVersion.application.name} - ${applicationVersion.version}"/>
    <jsp:param name="buttons" value='<a id="addDependencyModalButton" href="#addDependencyModal" role="button" class="btn" data-toggle="modal">Add Dependency</a>'/>
    <jsp:param name="content" value="applicationVersion"/>
</jsp:include>