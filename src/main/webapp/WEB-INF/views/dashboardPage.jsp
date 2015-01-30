<%@taglib uri="http://www.springframework.org/tags" prefix="spring"%>

<spring:message code="label.dashboard" var="title"/>
<spring:message code="label.trend.year" var="yearLabel"/>
<spring:message code="label.trend.quarter" var="quarterLabel"/>
<spring:message code="label.trend.month" var="monthLabel"/>
<spring:message code="label.trend.week" var="weekLabel"/>

<jsp:include page="/WEB-INF/views/templates/page.jsp">
    <jsp:param name="title" value="${title}"/>
    <jsp:param name="buttons" value='
        <div class="btn-group" data-toggle="buttons-radio">
            <button type="button" class="trendButton btn btn-small" data-id="365" id="trendYearButton">${yearLabel}</button>
            <button type="button" class="trendButton btn btn-small" data-id="90" id="trendQuarterButton">${quarterLabel}</button>
            <button type="button" class="trendButton btn btn-small" data-id="30" id="trendMonthButton">${monthLabel}</button>
            <button type="button" class="trendButton btn btn-small" data-id="7" id="trendWeekButton">${weekLabel}</button>
        </div>
    '/>
    <jsp:param name="content" value="dashboard"/>
</jsp:include>