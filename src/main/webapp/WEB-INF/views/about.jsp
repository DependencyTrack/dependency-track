<%@taglib uri="http://www.springframework.org/tags" prefix="spring"%>
<%@taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<%@taglib uri="https://www.owasp.org/index.php/OWASP_Java_Encoder_Project" prefix="e"%>

<img src="<c:url value='/resources/images/dependency-track-logo.png'/>" alt="Dependency-Track Logo" style="margin-bottom:20px;"/>
<p>
    <e:forHtmlContent value="${properties.shortname}"/> is a web application that allows organizations to document the use of third-party components
    across multiple applications and versions.
</p>

<p>
    The <a href="https://www.owasp.org/index.php/Top_10_2013">OWASP Top Ten 2013</a> introduces, for the first time,
    the use of third-party components with known vulnerabilities. <e:forHtmlContent value="${properties.shortname}"/>
    aims to document the usage of all components, the vendors, libraries, versions and licenses used and provide
    visibility into the use of vulnerable components.
</p>

<p>
    Additional information can be found on the
    <a href="https://www.owasp.org/index.php/OWASP_Dependency_Track_Project"><e:forHtmlContent value="${properties.longname}"/> Project Page</a>.
</p>

<pre>
    <spring:message code="label.version"/>:    <e:forHtmlContent value="${properties.version}"/>
    <spring:message code="label.date.build"/>: <e:forHtmlContent value="${properties.builddate} "/>
</pre>