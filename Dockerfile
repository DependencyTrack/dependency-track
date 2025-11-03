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
FROM maven:3.9.8-eclipse-temurin-17 AS backend-builder
WORKDIR /app/backend
COPY pom.xml .
RUN mvn -q -e -U dependency:go-offline
COPY . .
RUN mvn -q -e clean package -DskipTests

# ===========================
# 3️⃣ FINAL IMAGE (Runtime)
# ===========================
FROM eclipse-temurin:17-jre-jammy
WORKDIR /app
COPY --from=backend-builder /app/backend/target/*.jar app.jar
COPY --from=frontend-builder /app/frontend/dist /app/static
EXPOSE 8080
ENTRYPOINT ["java","-jar","app.jar"]
