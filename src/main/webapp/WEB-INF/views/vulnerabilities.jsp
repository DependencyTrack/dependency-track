<%@taglib uri="http://www.springframework.org/tags" prefix="spring"%>
<%@taglib uri="http://www.springframework.org/tags/form" prefix="form"%>
<%@taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<%@taglib uri="http://java.sun.com/jsp/jstl/functions" prefix="fn"%>
<%@taglib uri="http://shiro.apache.org/tags" prefix="shiro"%>
<%@taglib uri="https://www.owasp.org/index.php/OWASP_Java_Encoder_Project" prefix="e"%>

<spring:message code="label.role.admin" var="admin"/>
<spring:message code="permissions.deleteDependency" var="deleteDependency"/>

<div id="applicationVersionContainer">
    <c:if test="${!empty applicationVersion}">

        <table id="vulnerabilitiesTable" class="list tablesorter">
            <thead>
            <tr>
                <th><spring:message code="label.vulnerable.component"/></th>
                <th width="100"><spring:message code="label.cvss.score"/></th>
                <th width="100"><spring:message code="label.severity"/></th>
            </tr>
            </thead>
            <tbody>
            <c:forEach items="${vulnerableComponents}" var="vulnerableComponent">
                <c:forEach items="${vulnerableComponent.vulnerabilities}" var="vulnerability">
                <tr>
                    <td style="padding-top:0; padding-bottom:20px; border-bottom:1px; border-color:#c0c0c0">
                        <table cellspacing="0" cellpadding="0" border="0" style="margin:0; padding:0;">
                            <tr>
                                <td><spring:message code="label.component"/>: </td>
                                <td><e:forHtmlContent value="${vulnerableComponent.libraryVersion.library.libraryname}"/> v<e:forHtmlContent value="${vulnerableComponent.libraryVersion.libraryversion}"/></td>
                            </tr>
                            <tr>
                                <td><spring:message code="label.vendor"/>: </td>
                                <td><e:forHtmlContent value="${vulnerableComponent.libraryVersion.library.libraryVendor.vendor}"/></td>
                            </tr>
                            <tr>
                                <td><spring:message code="label.cve.id"/>: </td>
                                <td><a href="http://web.nvd.nist.gov/view/vuln/detail?vulnId=<e:forHtmlAttribute value="${vulnerability.name}"/>"><e:forHtmlContent value="${vulnerability.name}"/></a></td>
                            </tr>
                            <tr>
                                <td><spring:message code="label.cwe.id"/>: </td>
                                <td><a href="http://cwe.mitre.org/data/definitions/<e:forHtmlAttribute value="${vulnerability.cweId}"/>.html"><e:forHtmlContent value="${vulnerability.cwe}"/></a></td>
                            </tr>
                            <tr>
                                <td><spring:message code="label.description"/>: </td>
                                <td><e:forHtmlContent value="${vulnerability.description}"/></td>
                            </tr>
                        </table>
                    </td>
                    <td style="vertical-align:top; padding-top: 8px; border-bottom:1px; border-color:#c0c0c0"><e:forHtmlContent value="${vulnerability.cvssScore}"/></td>
                    <td style="vertical-align:top; border-bottom:1px; border-color:#c0c0c0"><e:forHtmlContent value="${vulnerability.severity}"/></td>
                </tr>
                </c:forEach>
            </c:forEach>
            </tbody>
        </table>
    </c:if>
</div>