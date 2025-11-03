# ===========================
# 1️⃣ FRONTEND BUILD (Node)
# ===========================
FROM node:18 AS frontend-builder
WORKDIR /app/frontend
COPY ../frontend/package*.json ./
RUN npm ci
COPY ../frontend/ .
RUN npm run build

# ===========================
# 2️⃣ BACKEND BUILD (Maven)
# ===========================
FROM maven:3.9.8-eclipse-temurin-21 AS backend-builder
WORKDIR /app/backend
COPY pom.xml .
RUN mvn -q -e -U dependency:go-offline
COPY . .
RUN mvn -q -e clean package -DskipTests

# ===========================
# 3️⃣ FINAL IMAGE (Runtime)
# ===========================
FROM jetty:23-jdk21
WORKDIR /var/lib/jetty
# Copy built WAR into Jetty webapps as ROOT.war
COPY --from=backend-builder /app/backend/target/*.war /var/lib/jetty/webapps/ROOT.war
# Copy frontend static files into Jetty webapps (adjust path as needed)
COPY --from=frontend-builder /app/frontend/dist /var/lib/jetty/webapps/static
EXPOSE 8080
# Jetty image provides its own startup; no custom ENTRYPOINT required
