<%@taglib uri="http://www.springframework.org/tags" prefix="spring" %>
<%@taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<%@taglib uri="https://www.owasp.org/index.php/OWASP_Java_Encoder_Project" prefix="e"%>

<div id="dashboardContainer">

    <div class="container-fluid">
        <div class="row-fluid">

            <c:if test="${!empty applicationList}">
                <div class="well sidebar-nav left">
                    <div class="accordion" id="questions">
                        <c:forEach items="${applicationList}" var="applicationList">
                            <div class="accordion-group">
                                <div class="accordion-heading">
                                    <a class="accordion-toggle btn nav-header" data-toggle="collapse"
                                       data-parent="#questions"
                                       href="#${applicationList.id}"><e:forHtmlContent value="${applicationList.name}"/></a>
                                </div>
                                <div id="${applicationList.id}" class="accordion-body collapse">
                                    <div class="accordion-inner">
                                        <c:forEach items="${applicationList.versions}" var="version">
                                            <a href="#" class="visualizeData" id="visualizeData"
                                               data-applicationid="${applicationList.id}"
                                               data-versionid="${version.id}">Version
                                               <e:forHtmlContent value="${version.version}"/></a>
                                            <br>
                                        </c:forEach>
                                    </div>
                                </div>
                            </div>
                        </c:forEach>
                    </div>
                </div>
            </c:if>

            <div class="content fixed-fixed ">
                <div class="row ">
                    <div class="span12 ">
                        <ul class="nav nav-tabs">
                            <li class="active">
                                <a href="#graphOne" data-toggle="tab"><spring:message code="label.dashboard.graphOne"/></a>
                            </li>
                            <li>
                                <a href="#graphTwo" data-toggle="tab"><spring:message code="label.dashboard.graphTwo"/></a>
                            </li>
                            <li>
                                <a href="#graphThree" data-toggle="tab"><spring:message code="label.dashboard.graphThree"/></a>
                            </li>
                        </ul>
                        <div class="tab-content">
                            <div class="tab-pane active" id="graphOne">
                                <div id="chart_divone" style="width: 100%;height: 100%; position: relative;"></div>
                                <div class="modal-footer"></div>
                            </div>
                            <div class="tab-pane" id="graphTwo">
                                <div id="chart_divtwo" style="width: 100%;height: 100%; position: relative;"></div>
                                <div class="modal-footer"></div>
                            </div>
                            <div class="tab-pane " id="graphThree">
                                <div id="chart_divthree" style="width: 100%;height: 100%; position: relative;"> ></div>
                                <div class="modal-footer"></div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>