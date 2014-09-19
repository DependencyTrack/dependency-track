<%@taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<%@taglib uri="https://www.owasp.org/index.php/OWASP_Java_Encoder_Project" prefix="e"%>

<div class="pageheader">
        <div class="logo">
            <a href="<c:url value="/"/>"><img  src="<c:url value="/resources/images/corner.png"/>" width="104" height="48" alt="OWASP Logo"/></a>
        </div>
        <span id="name"><e:forHtmlContent value="${properties.longname}"/></span>
    </div>