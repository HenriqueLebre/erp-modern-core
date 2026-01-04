/*
 * AuthAPI.prg - XHarbour HTTP Wrapper for Modern Auth API
 * 
 * This demonstrates how the legacy XHarbour ERP system integrates
 * with the modern .NET 8 Auth API using HTTP calls.
 * 
 * Part of the Strangler Fig migration pattern - gradually replacing
 * legacy authentication while maintaining system operation.
 */

#include "hbcurl.ch"

// Global variables for auth state
STATIC s_authToken := ""
STATIC s_currentUser := NIL
STATIC s_apiBaseUrl := "http://localhost:5281"

/*
 * Main Authentication Class for Legacy System
 */
CLASS TAuthAPI
   DATA cBaseUrl
   DATA cToken
   DATA lAuthenticated
   DATA oUser
   
   METHOD New(cBaseUrl)
   METHOD Login(cUsername, cPassword)
   METHOD ValidateToken(cToken)
   METHOD GetCurrentUser()
   METHOD Logout()
   METHOD IsAuthenticated()
   
   // Internal HTTP methods
   METHOD HttpPost(cEndpoint, cJsonData)
   METHOD HttpGet(cEndpoint)
   METHOD BuildAuthHeader()
ENDCLASS

/*
 * Constructor - Initialize Auth API wrapper
 */
METHOD New(cBaseUrl) CLASS TAuthAPI
   ::cBaseUrl := iif(Empty(cBaseUrl), "http://localhost:5281", cBaseUrl)
   ::cToken := ""
   ::lAuthenticated := .F.
   ::oUser := NIL
RETURN Self

/*
 * Login Method - Authenticate user with modern API
 * 
 * This replaces the legacy authentication that was previously
 * done directly against the XHarbour database.
 */
METHOD Login(cUsername, cPassword) CLASS TAuthAPI
   LOCAL cJsonRequest, cResponse, oResult, lSuccess := .F.
   
   // Build JSON request
   cJsonRequest := '{'
   cJsonRequest += '"username":"' + cUsername + '",'
   cJsonRequest += '"password":"' + cPassword + '"'
   cJsonRequest += '}'
   
   // Call modern Auth API
   cResponse := ::HttpPost("/auth/login", cJsonRequest)
   
   IF !Empty(cResponse)
      oResult := JsonDecode(cResponse)
      
      IF oResult != NIL .AND. oResult:success == .T.
         // Successfully authenticated
         ::cToken := oResult:token
         ::lAuthenticated := .T.
         
         // Get user details
         ::GetCurrentUser()
         
         // Store token globally for other legacy functions
         s_authToken := ::cToken
         s_currentUser := ::oUser
         
         ? "✅ Login successful for user:", cUsername
         ? "🔑 Token obtained (first 20 chars):", Left(::cToken, 20) + "..."
         
         lSuccess := .T.
      ELSE
         ? "❌ Login failed:", iif(oResult != NIL, oResult:message, "Unknown error")
      ENDIF
   ELSE
      ? "❌ Failed to connect to Auth API at:", ::cBaseUrl
   ENDIF
   
RETURN lSuccess

/*
 * Validate Token - Check if current token is still valid
 * 
 * This is called by legacy functions before performing sensitive operations
 * like opening POS terminal or processing payments.
 */
METHOD ValidateToken(cToken) CLASS TAuthAPI
   LOCAL cJsonRequest, cResponse, oResult, lValid := .F.
   
   IF Empty(cToken)
      cToken := ::cToken
   ENDIF
   
   IF Empty(cToken)
      ? "❌ No token to validate"
      RETURN .F.
   ENDIF
   
   // Build JSON request
   cJsonRequest := '{"token":"' + cToken + '"}'
   
   // Call validation endpoint
   cResponse := ::HttpPost("/auth/validate", cJsonRequest)
   
   IF !Empty(cResponse)
      oResult := JsonDecode(cResponse)
      
      IF oResult != NIL .AND. oResult:success == .T. .AND. oResult:valid == .T.
         ? "✅ Token is valid for user:", oResult:username
         ? "👤 User ID:", oResult:userId
         ? "🔐 Role:", oResult:role
         
         lValid := .T.
      ELSE
         ? "❌ Token validation failed:", iif(oResult != NIL, oResult:message, "Invalid token")
         ::Logout() // Clear invalid token
      ENDIF
   ELSE
      ? "❌ Failed to validate token - API unreachable"
   ENDIF
   
RETURN lValid

/*
 * Get Current User - Retrieve user information using JWT token
 */
METHOD GetCurrentUser() CLASS TAuthAPI
   LOCAL cResponse, oResult
   
   IF Empty(::cToken)
      ? "❌ No authentication token available"
      RETURN NIL
   ENDIF
   
   // Call /auth/me endpoint with Bearer token
   cResponse := ::HttpGet("/auth/me")
   
   IF !Empty(cResponse)
      oResult := JsonDecode(cResponse)
      
      IF oResult != NIL
         ::oUser := oResult
         ? "👤 Current user:", oResult:username
         ? "🆔 User ID:", oResult:userId  
         ? "🔐 Role:", oResult:role
      ENDIF
   ENDIF
   
RETURN ::oUser

/*
 * Logout - Clear authentication state
 */
METHOD Logout() CLASS TAuthAPI
   ::cToken := ""
   ::lAuthenticated := .F.
   ::oUser := NIL
   s_authToken := ""
   s_currentUser := NIL
   
   ? "🚪 User logged out successfully"
RETURN .T.

/*
 * Check if user is authenticated
 */
METHOD IsAuthenticated() CLASS TAuthAPI
RETURN ::lAuthenticated .AND. !Empty(::cToken)

/*
 * HTTP POST Helper
 */
METHOD HttpPost(cEndpoint, cJsonData) CLASS TAuthAPI
   LOCAL curl, cUrl, cResponse := ""
   
   cUrl := ::cBaseUrl + cEndpoint
   
   curl := curl_easy_init()
   IF curl != NIL
      curl_easy_setopt(curl, CURLOPT_URL, cUrl)
      curl_easy_setopt(curl, CURLOPT_POSTFIELDS, cJsonData)
      curl_easy_setopt(curl, CURLOPT_HTTPHEADER, {"Content-Type: application/json"})
      curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, {|cData| cResponse += cData, Len(cData)})
      
      IF curl_easy_perform(curl) == CURLE_OK
         // Success
      ELSE
         ? "❌ HTTP request failed to:", cUrl
      ENDIF
      
      curl_easy_cleanup(curl)
   ENDIF
   
RETURN cResponse

/*
 * HTTP GET Helper with Authorization header
 */
METHOD HttpGet(cEndpoint) CLASS TAuthAPI
   LOCAL curl, cUrl, cResponse := "", aHeaders := {}
   
   cUrl := ::cBaseUrl + cEndpoint
   
   // Add Authorization header if we have a token
   IF !Empty(::cToken)
      AAdd(aHeaders, "Authorization: Bearer " + ::cToken)
   ENDIF
   AAdd(aHeaders, "Content-Type: application/json")
   
   curl := curl_easy_init()
   IF curl != NIL
      curl_easy_setopt(curl, CURLOPT_URL, cUrl)
      curl_easy_setopt(curl, CURLOPT_HTTPHEADER, aHeaders)
      curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, {|cData| cResponse += cData, Len(cData)})
      
      IF curl_easy_perform(curl) == CURLE_OK
         // Success
      ELSE
         ? "❌ HTTP GET request failed to:", cUrl
      ENDIF
      
      curl_easy_cleanup(curl)
   ENDIF
   
RETURN cResponse

/*
 * Build Authorization Header
 */
METHOD BuildAuthHeader() CLASS TAuthAPI
   LOCAL cHeader := ""
   
   IF !Empty(::cToken)
      cHeader := "Bearer " + ::cToken
   ENDIF
   
RETURN cHeader

//
// GLOBAL FUNCTIONS FOR LEGACY SYSTEM INTEGRATION
//

/*
 * Legacy Function: CheckUserPermission()
 * 
 * This function is called throughout the legacy system to check
 * if the current user has permission to perform sensitive operations.
 * 
 * BEFORE: Checked against local XHarbour database
 * AFTER: Validates JWT token with modern Auth API
 */
FUNCTION CheckUserPermission(cPermission)
   LOCAL oAuth, lHasPermission := .F.
   
   // If no global token, user is not authenticated
   IF Empty(s_authToken)
      ? "❌ User not authenticated - permission denied:", cPermission
      RETURN .F.
   ENDIF
   
   // Validate current token
   oAuth := TAuthAPI():New()
   IF oAuth:ValidateToken(s_authToken)
      // Token is valid, check user role/permissions
      IF s_currentUser != NIL
         // Simple role-based check (can be extended)
         DO CASE
            CASE s_currentUser:role == "Admin"
               lHasPermission := .T. // Admin can do everything
               
            CASE s_currentUser:role == "Cashier" .AND. cPermission $ "POS,SALES,PAYMENT"
               lHasPermission := .T. // Cashier can access POS functions
               
            CASE s_currentUser:role == "Manager" .AND. !(cPermission $ "SYSTEM,CONFIG")
               lHasPermission := .T. // Manager can do most things
               
            OTHERWISE
               lHasPermission := .F. // No permission
         ENDCASE
         
         ? iif(lHasPermission, "✅", "❌") + " Permission check:", cPermission, "for role:", s_currentUser:role
      ENDIF
   ELSE
      ? "❌ Token validation failed - permission denied:", cPermission
   ENDIF
   
RETURN lHasPermission

/*
 * Legacy Function: OpenPOSTerminal()
 * 
 * This is an example of how a critical legacy function now
 * validates authentication through the modern API before proceeding.
 */
FUNCTION OpenPOSTerminal()
   LOCAL lCanOpen := .F.
   
   ? ""
   ? "🏪 Attempting to open POS terminal..."
   
   // Check permission using modern auth system
   IF CheckUserPermission("POS")
      ? "✅ POS terminal access granted"
      ? "🖥️  Opening POS interface..."
      
      // Here would be the actual POS terminal code
      // ...legacy POS functionality...
      
      lCanOpen := .T.
   ELSE
      ? "❌ POS terminal access denied - insufficient permissions"
      ? "💡 Please login with appropriate credentials"
   ENDIF
   
RETURN lCanOpen

/*
 * Legacy Function: ProcessPayment()
 * 
 * Another example of legacy function with modern auth integration
 */
FUNCTION ProcessPayment(nAmount, cPaymentType)
   ? ""
   ? "💳 Processing payment:", nAmount, cPaymentType
   
   // Always validate auth for financial operations
   IF CheckUserPermission("PAYMENT")
      ? "✅ Payment processing authorized"
      
      // Simulate payment processing
      ? "🔄 Connecting to payment gateway..."
      ? "✅ Payment processed successfully:", nAmount
      
      RETURN .T.
   ELSE
      ? "❌ Payment processing denied - authentication required"
      RETURN .F.
   ENDIF
   
RETURN .F.

//
// DEMONSTRATION MAIN PROGRAM
//
PROCEDURE Main()
   LOCAL oAuth
   
   ? "🚀 XHarbour Legacy Integration Demo"
   ? "=================================="
   ? ""
   
   // Initialize Auth API wrapper
   oAuth := TAuthAPI():New("http://localhost:5281")
   
   ? "📡 Connecting to Modern Auth API..."
   ? ""
   
   // Demo 1: Successful Login
   ? "🔐 Demo 1: User Authentication"
   ? "-----------------------------"
   IF oAuth:Login("admin", "admin")
      ? "🎉 Authentication successful!"
      ? ""
      
      // Demo 2: POS Terminal Access
      ? "🏪 Demo 2: POS Terminal Access"
      ? "-----------------------------"
      OpenPOSTerminal()
      ? ""
      
      // Demo 3: Payment Processing
      ? "💳 Demo 3: Payment Processing"
      ? "----------------------------"
      ProcessPayment(150.75, "Credit Card")
      ? ""
      
      // Demo 4: Token Validation
      ? "🔍 Demo 4: Token Validation"
      ? "---------------------------"
      oAuth:ValidateToken()
      ? ""
      
      // Demo 5: Get Current User Info  
      ? "👤 Demo 5: Current User Info"
      ? "---------------------------"
      oAuth:GetCurrentUser()
      ? ""
      
   ELSE
      ? "❌ Authentication failed - cannot proceed with demos"
   ENDIF
   
   // Demo 6: Failed Login Attempt
   ? "🚫 Demo 6: Failed Login Attempt"
   ? "------------------------------"
   oAuth:Login("hacker", "wrongpass")
   ? ""
   
   ? "🏁 Demo completed!"
   ? ""
   ? "📋 Integration Summary:"
   ? "====================="
   ? "✅ Legacy XHarbour system successfully integrated with modern .NET 8 Auth API"
   ? "✅ JWT tokens validated for all sensitive operations"  
   ? "✅ Role-based permissions enforced"
   ? "✅ Graceful fallback handling for API unavailability"
   ? "✅ Strangler Fig pattern - gradual migration while maintaining operation"

RETURN
*******************************************************************************
* PROTOCOL HANDLER - Recebe chamada sysfood://
*******************************************************************************
FUNCTION ProtocolHandler(cUrl)
    LOCAL cToken := ""
    LOCAL cApiUrl := "http://localhost:5281"
    LOCAL lValid := .F.
    
    * Extrair token da URL (sysfood://launch?token=XXX)
    IF "token=" $ LOWER(cUrl)
        cToken := SubStr(cUrl, At("token=", LOWER(cUrl)) + 6)
        
        * Remover possível & ou outros parâmetros
        IF "&" $ cToken
            cToken := Left(cToken, At("&", cToken) - 1)
        ENDIF
        
        ? "🔐 Token recebido via protocol handler"
        ? "Token:", Left(cToken, 50) + "..."
        
        * Validar token na API
        lValid := ValidateToken(cApiUrl, cToken)
        
        IF lValid
            ? "✅ Token válido! Abrindo ERP..."
            
            * Aqui você iniciaria sua aplicação principal
            * Por enquanto, só mostramos mensagem
            WAIT "ERP Autenticado! Pressione qualquer tecla..."
            
            RETURN .T.
        ELSE
            ? "❌ Token inválido!"
            WAIT "Autenticação falhou. Pressione qualquer tecla..."
            RETURN .F.
        ENDIF
    ELSE
        ? "❌ Token não encontrado na URL"
        RETURN .F.
    ENDIF
RETURN .F.

*******************************************************************************
* VALIDAR TOKEN NA API
*******************************************************************************
FUNCTION ValidateToken(cApiUrl, cToken)
    LOCAL oHttp
    LOCAL cResponse := ""
    LOCAL lValid := .F.
    LOCAL cUrl := cApiUrl + "/auth/validate"
    
    ? "🔍 Validando token na API..."
    ? "URL:", cUrl
    
    TRY
        * Criar objeto HTTP
        oHttp := CreateObject("WinHttp.WinHttpRequest.5.1")
        
        * Configurar request
        oHttp:Open("POST", cUrl, .F.)
        oHttp:SetRequestHeader("Content-Type", "application/json")
        
        * Body com token
        cBody := '{"token":"' + cToken + '"}'
        
        * Enviar request
        oHttp:Send(cBody)
        
        * Ler resposta
        cResponse := oHttp:ResponseText
        
        ? "Resposta API:", cResponse
        
        * Verificar se validação foi bem-sucedida
        * (Ajuste de acordo com a resposta da sua API)
        IF oHttp:Status == 200
            lValid := .T.
            ? "✅ Token validado com sucesso!"
        ELSE
            ? "❌ Token inválido (Status:", oHttp:Status, ")"
        ENDIF
        
    CATCH oErr
        ? "❌ Erro ao validar token:", oErr:Description
        lValid := .F.
    END TRY
    
RETURN lValid

*******************************************************************************
* MAIN - Ponto de entrada do programa
*******************************************************************************
PROCEDURE Main()
    LOCAL cCommandLine := GetCommandLine()
    
    ? "============================================"
    ? "  SysFood ERP - Protocol Handler"
    ? "============================================"
    ? ""
    
    * Se foi chamado via protocol handler (sysfood://...)
    IF "sysfood://" $ LOWER(cCommandLine)
        ? "📞 Chamado via protocol handler"
        ? "Linha de comando:", cCommandLine
        ? ""
        
        ProtocolHandler(cCommandLine)
    ELSE
        * Modo normal (sem protocol handler)
        ? "ℹ️  Iniciando em modo normal..."
        ? ""
        
        * Seu código normal do ERP aqui
        WAIT "Modo normal. Pressione qualquer tecla..."
    ENDIF
    
RETURN

*******************************************************************************
* GetCommandLine - Retorna linha de comando completa
*******************************************************************************
FUNCTION GetCommandLine()
    LOCAL cLine := ""
    LOCAL i
    
    * Concatenar todos os parâmetros
    FOR i := 0 TO PCount()
        cLine += hb_PValue(i) + " "
    NEXT
    
RETURN AllTrim(cLine)