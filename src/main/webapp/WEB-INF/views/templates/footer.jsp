<%@taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<%@taglib uri="http://www.springframework.org/tags" prefix="spring" %>
<%@taglib uri="http://shiro.apache.org/tags" prefix="shiro"%>
<%@taglib uri="https://www.owasp.org/index.php/OWASP_Java_Encoder_Project" prefix="e"%>
<spring:eval var="longname" expression="@environment.getProperty('longname')" />
<spring:eval var="version" expression="@environment.getProperty('version')" />
    <div class="footer">
        <spring:message code="permissions.about" var="about"/>
        <shiro:hasPermission name="${about}">
        <div class="identifier"><e:forHtmlContent value="${longname}"/> v<e:forHtmlContent value="${version}"/></div>
        </shiro:hasPermission>
    </div>