<%@taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<%@taglib uri="https://www.owasp.org/index.php/OWASP_Java_Encoder_Project" prefix="e"%>
<%@taglib prefix="spring" uri="http://www.springframework.org/tags" %>
<spring:eval var="longname" expression="@environment.getProperty('longname')" />
<div class="pageheader">
        <div class="logo">
            <a href="<c:url value="/"/>"><img  src="<c:url value="/resources/images/corner.png"/>" width="104" height="48" alt="OWASP Logo"/></a>
        </div>
        <span id="name"><e:forHtmlContent value="${longname}"/></span>
    </div>