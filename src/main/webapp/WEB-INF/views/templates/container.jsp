<%@ page import="java.util.Map" %>
<%@ page import="java.util.HashMap" %>
<%@ page import="org.owasp.html.PolicyFactory" %>
<%@ page import="org.owasp.html.HtmlPolicyBuilder" %>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<%@ taglib prefix="fn" uri="http://java.sun.com/jsp/jstl/functions" %>
<%@ taglib prefix="e" uri="https://www.owasp.org/index.php/OWASP_Java_Encoder_Project" %>

<%!
    /*
        The value of param.content passed to this template must match the white-list
        defined in the following map.
     */
    private static final Map<String,String> contentWhitelist = new HashMap<String,String>() {{
        put("about", "about.jsp");
        put("usermanagement", "userManagement.jsp");
        put("dashboard","dashboard.jsp");
        put("applications", "applications.jsp");
        put("applicationVersion", "applicationVersion.jsp");
        put("vulnerabilities", "vulnerabilities.jsp");
        put("error", "error.jsp");
        put("libraries", "libraries.jsp");
        put("403", "403.jsp");
    }};

    private static final PolicyFactory htmlButtonPolicy = new HtmlPolicyBuilder()
        .allowElements("a")
        .allowAttributes("href").onElements("a")
        .allowAttributes("id").onElements("a")
        .allowAttributes("role").onElements("a")
        .allowAttributes("class").onElements("a")
        .allowAttributes("data-toggle").onElements("a")
        .allowAttributes("data-id").onElements("a")
        .allowAttributes("data-ver").onElements("a")
        .allowAttributes("data-version").onElements("a")
        .allowElements("button")
        .allowAttributes("type").onElements("button")
        .allowAttributes("id").onElements("button")
        .allowAttributes("class").onElements("button")
        .allowAttributes("data-toggle").onElements("button")
        .allowAttributes("data-id").onElements("button")
        .allowElements("div")
        .allowAttributes("class").onElements("div")
        .allowAttributes("data-toggle").onElements("div")
        .toFactory();
%>
<%
    pageContext.setAttribute("contentWhitelist", contentWhitelist);
    pageContext.setAttribute("htmlButtonPolicy", htmlButtonPolicy);
%>

<div class="content-outer-container">
    <div class="content-inner-container">
        <div class="title-container">
            <div class="title"><e:forHtmlContent value="${param.title}"/></div>
            <div class="title-buttons">${htmlButtonPolicy.sanitize(param.buttons)}</div>
        </div>
        <div class="content">
            <c:set var="contentPage" value="${contentWhitelist[param.content]}"/>
            <jsp:include page="/WEB-INF/views/${contentPage}"/>
        </div>
    </div>
</div>