# ==================================
# Stage 1: Base Runtime Image
# ==================================
FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS base
WORKDIR /app
EXPOSE 80
EXPOSE 443

# Create non-root user for security
RUN addgroup --system --gid 1001 appuser && \
    adduser --system --uid 1001 --ingroup appuser appuser

# ==================================
# Stage 2: Build
# ==================================
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
ARG BUILD_CONFIGURATION=Release
WORKDIR /src

# Copy all source code first (simpler approach)
COPY src/ .

# Restore dependencies
RUN dotnet restore "Modules/Auth/Auth.API/Auth.API.csproj"

# Build
WORKDIR "/src/Modules/Auth/Auth.API"
RUN dotnet build "Auth.API.csproj" -c $BUILD_CONFIGURATION -o /app/build

# ==================================
# Stage 3: Publish
# ==================================
FROM build AS publish
ARG BUILD_CONFIGURATION=Release
RUN dotnet publish "Auth.API.csproj" \
    -c $BUILD_CONFIGURATION \
    -o /app/publish \
    /p:UseAppHost=false

# ==================================
# Stage 4: Final Runtime Image
# ==================================
FROM base AS final
WORKDIR /app

# Copy published files
COPY --from=publish /app/publish .

# Switch to non-root user
USER appuser

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=60s --retries=3 \
    CMD curl --fail http://localhost/health || exit 1

# Entry point
ENTRYPOINT ["dotnet", "Auth.API.dll"]
