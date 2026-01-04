FROM mcr.microsoft.com/dotnet/sdk:8.0-alpine AS build
WORKDIR /src

COPY ["ERP.Modern.sln", "./"]
COPY ["src/Modules/Auth/Auth.API/Auth.API.csproj", "src/Modules/Auth/Auth.API/"]
COPY ["src/Modules/Auth/Auth.Application/Auth.Application.csproj", "src/Modules/Auth/Auth.Application/"]
COPY ["src/Modules/Auth/Auth.Domain/Auth.Domain.csproj", "src/Modules/Auth/Auth.Domain/"]
COPY ["src/Modules/Auth/Auth.Infrastructure/Auth.Infrastructure.csproj", "src/Modules/Auth/Auth.Infrastructure/"]
COPY ["src/BuildingBlocks/SharedKernel.Application/SharedKernel.Application.csproj", "src/BuildingBlocks/SharedKernel.Application/"]
COPY ["src/BuildingBlocks/SharedKernel.Domain/SharedKernel.Domain.csproj", "src/BuildingBlocks/SharedKernel.Domain/"]

RUN dotnet restore "src/Modules/Auth/Auth.API/Auth.API.csproj"

COPY . .

WORKDIR "/src/src/Modules/Auth/Auth.API"
RUN dotnet build "Auth.API.csproj" -c Release -o /app/build

FROM build AS publish
RUN dotnet publish "Auth.API.csproj" -c Release -o /app/publish /p:UseAppHost=false

FROM mcr.microsoft.com/dotnet/aspnet:8.0-alpine AS runtime
WORKDIR /app

# Criar usuário não-root para segurança
RUN addgroup -g 1000 appuser && \
    adduser -u 1000 -G appuser -s /bin/sh -D appuser && \
    chown -R appuser:appuser /app

# Copiar binários publicados
COPY --from=publish /app/publish .

USER appuser

# Expor porta
EXPOSE 8080

# Healthcheck
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8080/health || exit 1

ENV ASPNETCORE_ENVIRONMENT=Production
ENV ASPNETCORE_URLS=http://+:8080

ENTRYPOINT ["dotnet", "Auth.API.dll"]