<%@taglib uri="http://www.springframework.org/tags" prefix="spring"%>
<%@taglib uri="http://shiro.apache.org/tags" prefix="shiro"%>
<spring:message code="label.unauthorized" var="title"/>
<shiro:authenticated>
  <jsp:include page="/WEB-INF/views/templates/page.jsp">
    <jsp:param name="title" value="${title}"/>
    <jsp:param name="content" value="403"/>
  </jsp:include>
</shiro:authenticated>
