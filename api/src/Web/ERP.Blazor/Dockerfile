FROM mcr.microsoft.com/dotnet/sdk:8.0-alpine AS build
WORKDIR /src

# Copiar solution e projetos
COPY ["ERP.Modern.sln", "./"]
COPY ["src/Web/ERP.Blazor/ERP.Blazor.csproj", "src/Web/ERP.Blazor/"]
COPY ["src/BuildingBlocks/SharedKernel.Application/SharedKernel.Application.csproj", "src/BuildingBlocks/SharedKernel.Application/"]
COPY ["src/BuildingBlocks/SharedKernel.Domain/SharedKernel.Domain.csproj", "src/BuildingBlocks/SharedKernel.Domain/"]

# Restaurar dependências
RUN dotnet restore "src/Web/ERP.Blazor/ERP.Blazor.csproj"

# Copiar código fonte
COPY . .

# Build
WORKDIR "/src/src/Web/ERP.Blazor"
RUN dotnet build "ERP.Blazor.csproj" -c Release -o /app/build

FROM build AS publish
RUN dotnet publish "ERP.Blazor.csproj" -c Release -o /app/publish /p:UseAppHost=false

FROM mcr.microsoft.com/dotnet/aspnet:8.0-alpine AS runtime
WORKDIR /app

# Criar usuário não-root
RUN addgroup -g 1000 appuser && \
    adduser -u 1000 -G appuser -s /bin/sh -D appuser && \
    chown -R appuser:appuser /app

# Copiar binários
COPY --from=publish /app/publish .

# Usar usuário não-root
USER appuser

# Expor porta
EXPOSE 8080

# Healthcheck (Blazor não tem endpoint /health por padrão, usa raiz)
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8080/ || exit 1

# Variáveis de ambiente
ENV ASPNETCORE_ENVIRONMENT=Production
ENV ASPNETCORE_URLS=http://+:8080

# Entry point
ENTRYPOINT ["dotnet", "ERP.Blazor.dll"]