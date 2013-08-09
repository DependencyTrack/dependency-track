<%@ page import="java.util.Map" %>
<%@ page import="java.util.HashMap" %>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<%@ taglib prefix="fn" uri="http://java.sun.com/jsp/jstl/functions" %>

<%!
    /*
        The value of param.content passed to this template must match the white-list
        defined in the following map.
     */
    private static final Map<String,String> contentWhitelist = new HashMap<String,String>() {{
        put("about", "about.jsp");
        put("applications", "applications.jsp");
        put("applicationVersion", "applicationVersion.jsp");
        put("error", "error.jsp");
        put("libraries", "libraries.jsp");
    }};
%>
<%
    pageContext.setAttribute("contentWhitelist", contentWhitelist);
%>

<div class="content-outer-container">
    <div class="content-inner-container">
        <div class="title-container">
            <div class="title"><c:out value="${param.title}"/></div>
            <div class="title-buttons">${param.buttons}</div>
        </div>
        <div class="content">
            <c:set var="contentPage" value="${contentWhitelist[param.content]}"/>
            <jsp:include page="/WEB-INF/views/${contentPage}"/>
        </div>
    </div>
</div>