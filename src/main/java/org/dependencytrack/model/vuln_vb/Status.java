package org.dependencytrack.model.vuln_vb;

public class Status {
    private String organizationName;
    private String userNameRequesting;
    private String userEmailRequesting;
    private String subscriptionEndDate;
    private String apiCallsAllowedPerMonth;
    private String apiCallsMadeThisMonth;
    private String vulnDbStatistics;
    private String rawStatus;

    public Status() {
    }

    public String getOrganizationName() {
        return this.organizationName;
    }

    public void setOrganizationName(String organizationName) {
        this.organizationName = organizationName;
    }

    public String getUserNameRequesting() {
        return this.userNameRequesting;
    }

    public void setUserNameRequesting(String userNameRequesting) {
        this.userNameRequesting = userNameRequesting;
    }

    public String getUserEmailRequesting() {
        return this.userEmailRequesting;
    }

    public void setUserEmailRequesting(String userEmailRequesting) {
        this.userEmailRequesting = userEmailRequesting;
    }

    public String getSubscriptionEndDate() {
        return this.subscriptionEndDate;
    }

    public void setSubscriptionEndDate(String subscriptionEndDate) {
        this.subscriptionEndDate = subscriptionEndDate;
    }

    public String getApiCallsAllowedPerMonth() {
        return this.apiCallsAllowedPerMonth;
    }

    public void setApiCallsAllowedPerMonth(String apiCallsAllowedPerMonth) {
        this.apiCallsAllowedPerMonth = apiCallsAllowedPerMonth;
    }

    public String getApiCallsMadeThisMonth() {
        return this.apiCallsMadeThisMonth;
    }

    public void setApiCallsMadeThisMonth(String apiCallsMadeThisMonth) {
        this.apiCallsMadeThisMonth = apiCallsMadeThisMonth;
    }

    public String getVulnDbStatistics() {
        return this.vulnDbStatistics;
    }

    public void setVulnDbStatistics(String vulnDbStatistics) {
        this.vulnDbStatistics = vulnDbStatistics;
    }

    public String getRawStatus() {
        return this.rawStatus;
    }

    public void setRawStatus(String rawStatus) {
        this.rawStatus = rawStatus;
    }
}
