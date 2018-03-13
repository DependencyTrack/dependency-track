---
title: Deploying Docker Container
category: Getting Started
chapter: 1
order: 1
---

Deploying with Docker is the easiest and fastest method of getting started. No prerequisites are required
other than an modern version of Docker. 

> The 'latest' tag in Docker Hub will always refer to the latest stable GA release. Consult the GitHub repo
> for instructions on how to run untested snapshot releases.

#### Running the latest stable release

```bash
# Pull the image from the Docker Hub OWASP repo
docker pull owasp/dependency-track

# Creates a dedicated volume where data can be stored outside the container
docker volume create --name dependency-track

# Run the container
docker run -d -p 8080:8080 --name dependency-track -v dependency-track:/data owasp/dependency-track
```

#### Running container behind proxy server

If running Docker behind a proxy server, specify the proxy settings in the `HTTPS_PROXY` or `HTTP_PROXY` 
environment variables. Dependency-Track checks for the existence of these variables and attempts to use
them when specified.