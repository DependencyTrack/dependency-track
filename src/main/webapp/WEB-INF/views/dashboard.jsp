<%@taglib uri="http://www.springframework.org/tags" prefix="spring"%>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>

<div id="dashboardContainer">

<div class="container-fluid">
    <div class="row-fluid">

    <c:if test="${!empty applicationList}">

        <div class="well sidebar-nav left">
            <div class="accordion" id="questions">
        <c:forEach items="${applicationList}" var="applicationList">
                 <div class="accordion-group">
                      <div class="accordion-heading">
                             <a class="accordion-toggle btn nav-header" data-toggle="collapse" data-parent="#questions" href="#${applicationList.id}"> ${applicationList.name} </a>
                      </div>
                  <div id="${applicationList.id}" class="accordion-body collapse">

                        <div class="accordion-inner">
                            <c:forEach items="${applicationList.versions}" var="version">
                                <a href="#"><c:out value="${version.version}"/></a>
                            </c:forEach>

                        </div>
                  </div>
                 </div>
        </c:forEach>
            </div>
        </div>

    </c:if>

        <div class="well sidebar-nav right">
            <ul class="nav nav-list">
                <li class="nav-header">Application Standing</li>
                <li><a href="#">AIS</a></li>
                <li><a href="#">Integrator</a></li>
                <li><a href="#">Passport</a></li>
                <li><a href="#">Mailgate</a></li>

            </ul>
        </div><!--/.well -->

        <div class="content fixed-fixed">
            <div class="hero-unit">
                <ul class="nav nav-pills">
                    <li class="nav-header"><a href="#"><spring:message code="label.dashboard.graphOne"/></a></li>
                    <li class="nav-header"><a href="#"><spring:message code="label.dashboard.graphTwo"/></a></li>
                    <li class="nav-header"><a href="#"><spring:message code="label.dashboard.graphThree"/></a></li>
                </ul>
            </div>
          </div>
    </div>
</div>


 </div>