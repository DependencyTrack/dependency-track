<%@taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>

<div class="pageheader">
        <div class="logo">
            <a href="${pageContext.request.contextPath}"><img  src="<c:url value="${pageContext.request.contextPath}/resources/images/corner.png"/>" width="104" height="48" alt="OWASP Logo"/></a>
        </div>
        <span id="name">${properties.longname}</span>
    </div>