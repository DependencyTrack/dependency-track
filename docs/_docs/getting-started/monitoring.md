---
title: Monitoring
category: Getting Started
chapter: 1
order: 10
---

Dependency-Track can be configured to expose system metrics using the
Prometheus [text-based exposition format](https://prometheus.io/docs/instrumenting/exposition_formats/#text-based-format).
They can then be collected and visualized using tools like [Prometheus](https://prometheus.io/) and [Grafana](https://grafana.com/).

To enable metrics exposition, set the `alpine.metrics.enable` property to `true` (see 
[Configuration]({{ site.baseurl }}{% link _docs/getting-started/configuration.md %})). Metrics will be exposed in 
the `/metrics` endpoint, which is not subject to access control. If protection is desired, it is recommended to add 
[basic authentication](https://prometheus.io/docs/guides/basic-auth/) at the reverse proxy or load balancer layer. 
A guide for NGINX can be found [here](https://docs.nginx.com/nginx/admin-guide/security-controls/configuring-http-basic-authentication/).

Because [Micrometer](https://micrometer.io/) is used to collect and expose metrics, common Grafana dashboards for
Micrometer should just work. An example Grafana dashboard is provided [here](/files/grafana-dashboard.json). Refer to the 
[Grafana documentation](https://grafana.com/docs/grafana/latest/dashboards/export-import/#import-dashboard) for 
instructions on how to import it.

> The example dashboard is meant to be a starting point. Users are strongly encouraged to explore the available metrics
> and build their own dashboards, tailored to their needs. The sample dashboard is not actively maintained by the project
> team, however community contributions are more than welcome.

![System Metrics in Grafana](/images/screenshots/monitoring-metrics-system.png)

![Event Metrics in Grafana](/images/screenshots/monitoring-metrics-events.png)
