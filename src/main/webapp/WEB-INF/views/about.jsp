<%@taglib uri="http://www.springframework.org/tags" prefix="spring"%>
<p>
    ${properties.shortname} is a web application that allows organizations to document the use of third-party components
    across multiple applications and versions.
</p>

<p>
    The <a href="https://www.owasp.org/index.php/Top_10_2013">OWASP Top Ten 2013</a> introduces, for the first time,
    the use of third-party components with known vulnerabilities. ${properties.shortname} aims to document the usage of
    all components, the vendors, libraries, versions and licenses used and provide visibility into the use of vulnerable
    components.
</p>

<p>
    Additional information can be found on the
    <a href="https://www.owasp.org/index.php/OWASP_Dependency_Track_Project">${properties.longname} Project Page</a>.
</p>

<pre>
    <spring:message code="label.version"/>:    ${properties.version}
    <spring:message code="label.date.build"/>: ${properties.builddate}
</pre>