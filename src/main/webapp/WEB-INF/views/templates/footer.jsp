<%@taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<%@taglib uri="http://www.springframework.org/tags" prefix="spring" %>
<%@taglib uri="http://shiro.apache.org/tags" prefix="shiro"%>
<%@taglib uri="https://www.owasp.org/index.php/OWASP_Java_Encoder_Project" prefix="e"%>

    <div class="footer">
        <spring:message code="permissions.about" var="about"/>
        <shiro:hasPermission name="${about}">
        <div class="identifier"><e:forHtmlContent value="${properties.longname}"/> v<e:forHtmlContent value="${properties.version}"/></div>
        </shiro:hasPermission>
    </div>