<%@taglib uri="http://www.springframework.org/tags" prefix="spring"%>

<spring:message code="label.dashboard" var="title"/>
<spring:message code="label.trend.year" var="yearLabel"/>
<spring:message code="label.trend.quarter" var="quarterLabel"/>
<spring:message code="label.trend.month" var="monthLabel"/>
<spring:message code="label.trend.week" var="weekLabel"/>

<jsp:include page="/WEB-INF/views/templates/page.jsp">
    <jsp:param name="title" value="${title}"/>
    <jsp:param name="buttons" value='
        <div class="btn-group">
        <a id="trendYearButton" role="button" class="trendButton btn" data-id="365">${yearLabel}</a>
        <a id="trendQuarterButton" role="button" class="trendButton btn" data-id="90">${quarterLabel}</a>
        <a id="trendMonthButton" role="button" class="trendButton btn" data-id="30">${monthLabel}</a>
        <a id="trendWeekButton" role="button" class="trendButton btn" data-id="7">${weekLabel}</a>
        </div>
    '/>
    <jsp:param name="content" value="dashboard"/>
</jsp:include>