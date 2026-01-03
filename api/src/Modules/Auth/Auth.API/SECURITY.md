# 🔐 Security Configuration Guide

## 🚨 Critical Security Setup

### 1. JWT Secret Key Configuration

**❌ NEVER commit JWT secrets to version control!**

#### Environment Variables (Recommended)
```bash
# Development
export JWT__KEY="your-super-secret-jwt-key-at-least-32-characters-long-for-security"
export JWT__ISSUER="ERP.Auth.API"
export JWT__AUDIENCE="ERP.Clients"
export JWT__EXPIRATIONINMINUTES="60"

# Windows PowerShell
$env:JWT__KEY="your-super-secret-jwt-key-at-least-32-characters-long-for-security"
$env:JWT__ISSUER="ERP.Auth.API" 
$env:JWT__AUDIENCE="ERP.Clients"
$env:JWT__EXPIRATIONINMINUTES="60"
```

#### Docker Compose (Development)
```yaml
services:
  auth-api:
    environment:
      - JWT__KEY=your-super-secret-jwt-key-at-least-32-characters-long-for-security
      - JWT__ISSUER=ERP.Auth.API
      - JWT__AUDIENCE=ERP.Clients
      - JWT__EXPIRATIONINMINUTES=60
```

#### AWS Production (Recommended)
```bash
# Use AWS Secrets Manager or Parameter Store
aws secretsmanager create-secret \
    --name "erp/auth/jwt-key" \
    --description "JWT signing key for ERP Auth API" \
    --secret-string "your-super-secret-jwt-key-at-least-32-characters-long-for-security"
```

### 2. Rate Limiting Configuration

The API now includes rate limiting to prevent brute force attacks:

- **Login endpoint**: 5 attempts per minute per IP
- **All other endpoints**: 30 requests per minute per IP
- **HTTP Status**: 429 (Too Many Requests) when limit exceeded

#### Customize Rate Limits
Modify `Program.cs` to adjust limits:
```csharp
options.GeneralRules = new List<RateLimitRule>
{
    new RateLimitRule
    {
        Endpoint = "POST:/auth/login",
        Period = "1m",
        Limit = 3 // More restrictive: 3 attempts per minute
    }
};
```

### 3. Health Checks Endpoints

The API provides health monitoring endpoints:

- **`/health`**: Overall application health
- **`/health/ready`**: Readiness check (includes database connectivity)
- **`/health/live`**: Liveness check (basic application status)

### 4. Database Connection Security

Ensure your connection string uses secure credentials:
```json
{
  "ConnectionStrings": {
    "DefaultConnection": "Server=localhost;Port=5432;Database=erp_auth;User Id=erp_user;Password=strong_password_here;"
  }
}
```

**For Production:**
- Use AWS RDS with IAM authentication
- Store connection strings in AWS Secrets Manager
- Use SSL/TLS encryption for database connections

## 🔍 Security Features Implemented

### ✅ Authentication & Authorization
- JWT tokens with configurable expiration
- Secure password hashing (PBKDF2 with 100k iterations)  
- Automatic legacy password migration
- Role-based authorization

### ✅ API Security
- Rate limiting (brute force protection)
- Token validation endpoint (`/auth/validate`)
- User information endpoint (`/auth/me`)
- Swagger UI with JWT authentication support

### ✅ Infrastructure Security
- Health checks for monitoring
- Database connection validation
- Configurable JWT secrets (external configuration)

## 🚀 Testing Security Features

### Test Rate Limiting
```bash
# This should succeed (first 5 attempts)
for i in {1..5}; do
  curl -X POST http://localhost:5281/auth/login \
    -H "Content-Type: application/json" \
    -d '{"username":"admin","password":"wrong"}'
done

# This should return 429 (rate limited)
curl -X POST http://localhost:5281/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"wrong"}'
```

### Test Token Validation
```bash
# 1. Get a valid token
TOKEN=$(curl -X POST http://localhost:5281/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin"}' | jq -r '.token')

# 2. Validate the token
curl -X POST http://localhost:5281/auth/validate \
  -H "Content-Type: application/json" \
  -d "{\"token\":\"$TOKEN\"}"
```

### Test Health Checks
```bash
curl http://localhost:5281/health
curl http://localhost:5281/health/ready
curl http://localhost:5281/health/live
```

## 🔧 Production Deployment Checklist

- [ ] JWT secrets stored in AWS Secrets Manager
- [ ] Database connection uses SSL/TLS
- [ ] Rate limiting configured for production traffic
- [ ] Health checks monitored by load balancer
- [ ] Logging configured for security events
- [ ] HTTPS enabled (disable HTTP)
- [ ] CORS configured for specific origins
- [ ] Security headers added (HSTS, CSP, etc.)

## 🚨 Security Monitoring

Monitor these security events:
- Failed login attempts (potential brute force)
- Rate limit violations (429 responses)
- Invalid token validation attempts
- Health check failures
- Database connection issues

## 📞 Support

For security issues or questions, contact the development team.