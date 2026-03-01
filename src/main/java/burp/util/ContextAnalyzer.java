package burp.util;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;

public class ContextAnalyzer {
    
    private final IExtensionHelpers helpers;
    
    public ContextAnalyzer(IExtensionHelpers helpers) {
        this.helpers = helpers;
    }
    
    public static class RequestContext {
        private String method;
        private String url;
        private String path;
        private List<String> parameters;
        private String contentType;
        private String requestBody;
        private String responseBody;
        private String serverHeader;
        private Set<String> technologies;
        private String identifiedVulnType;
        private List<String> cookies;
        private Set<String> frameworks;
        private Set<String> databases;
        private List<String> missingSecurityHeaders;
        private String poweredBy;
        private Set<String> frontendFrameworks;
        private Set<String> backendFrameworks;
        private String host;
        private int port;
        private boolean isHttps;
        private String userAgent;
        private String authorization;
        
        public String getMethod() { return method; }
        public void setMethod(String method) { this.method = method; }
        public String getUrl() { return url; }
        public void setUrl(String url) { this.url = url; }
        public String getPath() { return path; }
        public void setPath(String path) { this.path = path; }
        public List<String> getParameters() { return parameters; }
        public void setParameters(List<String> parameters) { this.parameters = parameters; }
        public String getContentType() { return contentType; }
        public void setContentType(String contentType) { this.contentType = contentType; }
        public String getRequestBody() { return requestBody; }
        public void setRequestBody(String requestBody) { this.requestBody = requestBody; }
        public String getResponseBody() { return responseBody; }
        public void setResponseBody(String responseBody) { this.responseBody = responseBody; }
        public String getServerHeader() { return serverHeader; }
        public void setServerHeader(String serverHeader) { this.serverHeader = serverHeader; }
        public Set<String> getTechnologies() { return technologies; }
        public void setTechnologies(Set<String> technologies) { this.technologies = technologies; }
        public String getIdentifiedVulnType() { return identifiedVulnType; }
        public void setIdentifiedVulnType(String identifiedVulnType) { this.identifiedVulnType = identifiedVulnType; }
        public List<String> getCookies() { return cookies; }
        public void setCookies(List<String> cookies) { this.cookies = cookies; }
        public Set<String> getFrameworks() { return frameworks; }
        public void setFrameworks(Set<String> frameworks) { this.frameworks = frameworks; }
        public Set<String> getDatabases() { return databases; }
        public void setDatabases(Set<String> databases) { this.databases = databases; }
        public List<String> getMissingSecurityHeaders() { return missingSecurityHeaders; }
        public void setMissingSecurityHeaders(List<String> missingSecurityHeaders) { this.missingSecurityHeaders = missingSecurityHeaders; }
        public String getPoweredBy() { return poweredBy; }
        public void setPoweredBy(String poweredBy) { this.poweredBy = poweredBy; }
        public Set<String> getFrontendFrameworks() { return frontendFrameworks; }
        public void setFrontendFrameworks(Set<String> frontendFrameworks) { this.frontendFrameworks = frontendFrameworks; }
        public Set<String> getBackendFrameworks() { return backendFrameworks; }
        public void setBackendFrameworks(Set<String> backendFrameworks) { this.backendFrameworks = backendFrameworks; }
        public String getHost() { return host; }
        public void setHost(String host) { this.host = host; }
        public int getPort() { return port; }
        public void setPort(int port) { this.port = port; }
        public boolean isHttps() { return isHttps; }
        public void setHttps(boolean isHttps) { this.isHttps = isHttps; }
        public String getUserAgent() { return userAgent; }
        public void setUserAgent(String userAgent) { this.userAgent = userAgent; }
        public String getAuthorization() { return authorization; }
        public void setAuthorization(String authorization) { this.authorization = authorization; }
        
        public void initializeCollections() {
            if (parameters == null) parameters = new ArrayList<>();
            if (technologies == null) technologies = new HashSet<>();
            if (cookies == null) cookies = new ArrayList<>();
            if (frameworks == null) frameworks = new HashSet<>();
            if (databases == null) databases = new HashSet<>();
            if (missingSecurityHeaders == null) missingSecurityHeaders = new ArrayList<>();
            if (frontendFrameworks == null) frontendFrameworks = new HashSet<>();
            if (backendFrameworks == null) backendFrameworks = new HashSet<>();
        }
    }
    
    public RequestContext analyzeRequest(IHttpRequestResponse message) {
        RequestContext context = new RequestContext();
        context.initializeCollections();
        
        if (message == null || message.getRequest() == null) {
            return context;
        }
        
        byte[] request = message.getRequest();
        
        try {
            analyzeHttpMethod(request, context);
            analyzeUrl(request, context);
            analyzeHeaders(request, context);
            analyzeCookies(request, context);
            analyzeParameters(request, context);
            analyzeBody(request, context);
            analyzeResponse(message, context);
            detectTechnologies(context);
            detectFrameworks(context);
            detectDatabases(context);
            analyzeSecurityHeaders(message, context);
        } catch (Exception e) {
            System.err.println("Failed to analyze request context: " + e.getMessage());
        }
        
        return context;
    }
    
    private void analyzeHttpMethod(byte[] request, RequestContext context) {
        String requestStr = new String(request, StandardCharsets.UTF_8);
        int spaceIndex = requestStr.indexOf(' ');
        if (spaceIndex > 0) {
            context.setMethod(requestStr.substring(0, spaceIndex).toUpperCase());
        }
    }
    
    private void analyzeUrl(byte[] request, RequestContext context) {
        String requestStr = new String(request, StandardCharsets.UTF_8);
        Pattern pathPattern = Pattern.compile("^[A-Z]+\\s+([^\\s]+)");
        Matcher matcher = pathPattern.matcher(requestStr);
        if (matcher.find()) {
            String fullPath = matcher.group(1);
            int queryIndex = fullPath.indexOf('?');
            String path = queryIndex > 0 ? fullPath.substring(0, queryIndex) : fullPath;
            context.setUrl(fullPath);
            context.setPath(path);
        }
        
        Pattern hostPattern = Pattern.compile("Host:\\s*([^\\r\\n]+)", Pattern.CASE_INSENSITIVE);
        Matcher hostMatcher = hostPattern.matcher(requestStr);
        if (hostMatcher.find()) {
            String hostHeader = hostMatcher.group(1).trim();
            int portIndex = hostHeader.indexOf(':');
            if (portIndex > 0) {
                context.setHost(hostHeader.substring(0, portIndex));
                try {
                    context.setPort(Integer.parseInt(hostHeader.substring(portIndex + 1)));
                } catch (NumberFormatException e) {
                    context.setPort(80);
                }
            } else {
                context.setHost(hostHeader);
                context.setPort(80);
            }
        }
    }
    
    private void analyzeHeaders(byte[] request, RequestContext context) {
        String requestStr = new String(request, StandardCharsets.UTF_8);
        
        Pattern contentTypePattern = Pattern.compile("Content-Type:\\s*([^\\r\\n]+)", Pattern.CASE_INSENSITIVE);
        Matcher ctMatcher = contentTypePattern.matcher(requestStr);
        if (ctMatcher.find()) {
            context.setContentType(ctMatcher.group(1).trim());
        }
        
        Pattern uaPattern = Pattern.compile("User-Agent:\\s*([^\\r\\n]+)", Pattern.CASE_INSENSITIVE);
        Matcher uaMatcher = uaPattern.matcher(requestStr);
        if (uaMatcher.find()) {
            context.setUserAgent(uaMatcher.group(1).trim());
        }
        
        Pattern authPattern = Pattern.compile("Authorization:\\s*([^\\r\\n]+)", Pattern.CASE_INSENSITIVE);
        Matcher authMatcher = authPattern.matcher(requestStr);
        if (authMatcher.find()) {
            context.setAuthorization(authMatcher.group(1).trim());
        }
    }
    
    private void analyzeCookies(byte[] request, RequestContext context) {
        String requestStr = new String(request, StandardCharsets.UTF_8);
        List<String> cookies = new ArrayList<>();
        
        Pattern cookiePattern = Pattern.compile("Cookie:\\s*([^\\r\\n]+)", Pattern.CASE_INSENSITIVE);
        Matcher cookieMatcher = cookiePattern.matcher(requestStr);
        if (cookieMatcher.find()) {
            String cookieHeader = cookieMatcher.group(1).trim();
            for (String cookie : cookieHeader.split(";")) {
                cookie = cookie.trim();
                if (!cookie.isEmpty()) {
                    int eqIndex = cookie.indexOf('=');
                    if (eqIndex > 0) {
                        cookies.add(cookie.substring(0, eqIndex).trim());
                    } else {
                        cookies.add(cookie);
                    }
                }
            }
        }
        context.setCookies(cookies);
    }
    
    private void analyzeParameters(byte[] request, RequestContext context) {
        List<String> params = new ArrayList<>();
        String requestStr = new String(request, StandardCharsets.UTF_8);
        
        Pattern queryPattern = Pattern.compile("\\?([^\\s]+)\\s+HTTP");
        Matcher queryMatcher = queryPattern.matcher(requestStr);
        if (queryMatcher.find()) {
            String queryString = queryMatcher.group(1);
            for (String param : queryString.split("&")) {
                int eqIndex = param.indexOf('=');
                if (eqIndex > 0) {
                    params.add(param.substring(0, eqIndex));
                }
            }
        }
        
        String contentType = context.getContentType();
        if (contentType != null && contentType.contains("application/x-www-form-urlencoded")) {
            int bodyStart = requestStr.indexOf("\r\n\r\n");
            if (bodyStart > 0) {
                String body = requestStr.substring(bodyStart + 4);
                for (String param : body.split("&")) {
                    int eqIndex = param.indexOf('=');
                    if (eqIndex > 0) {
                        params.add(param.substring(0, eqIndex));
                    }
                }
            }
        }
        
        Pattern jsonParamPattern = Pattern.compile("\"([^\"]+)\"\\s*:");
        if (contentType != null && contentType.contains("application/json")) {
            int bodyStart = requestStr.indexOf("\r\n\r\n");
            if (bodyStart > 0) {
                String body = requestStr.substring(bodyStart + 4);
                Matcher jsonMatcher = jsonParamPattern.matcher(body);
                while (jsonMatcher.find()) {
                    params.add(jsonMatcher.group(1));
                }
            }
        }
        
        context.setParameters(params);
    }
    
    private void analyzeBody(byte[] request, RequestContext context) {
        String requestStr = new String(request, StandardCharsets.UTF_8);
        int bodyStart = requestStr.indexOf("\r\n\r\n");
        if (bodyStart > 0 && bodyStart + 4 < requestStr.length()) {
            context.setRequestBody(requestStr.substring(bodyStart + 4));
        }
    }
    
    private void analyzeResponse(IHttpRequestResponse message, RequestContext context) {
        if (message.getResponse() != null) {
            String responseStr = new String(message.getResponse(), StandardCharsets.UTF_8);
            
            int bodyStart = responseStr.indexOf("\r\n\r\n");
            if (bodyStart > 0 && bodyStart + 4 < responseStr.length()) {
                String body = responseStr.substring(bodyStart + 4);
                context.setResponseBody(body.length() > 2000 ? body.substring(0, 2000) : body);
            }
            
            Pattern serverPattern = Pattern.compile("Server:\\s*([^\\r\\n]+)", Pattern.CASE_INSENSITIVE);
            Matcher serverMatcher = serverPattern.matcher(responseStr);
            if (serverMatcher.find()) {
                context.setServerHeader(serverMatcher.group(1).trim());
            }
            
            Pattern poweredByPattern = Pattern.compile("X-Powered-By:\\s*([^\\r\\n]+)", Pattern.CASE_INSENSITIVE);
            Matcher poweredByMatcher = poweredByPattern.matcher(responseStr);
            if (poweredByMatcher.find()) {
                context.setPoweredBy(poweredByMatcher.group(1).trim());
            }
        }
    }
    
    private void detectTechnologies(RequestContext context) {
        Set<String> techs = context.getTechnologies();
        
        String server = context.getServerHeader();
        if (server != null) {
            String serverLower = server.toLowerCase();
            if (serverLower.contains("nginx")) techs.add("Nginx");
            if (serverLower.contains("apache")) techs.add("Apache");
            if (serverLower.contains("iis")) techs.add("IIS");
            if (serverLower.contains("tomcat")) techs.add("Tomcat");
            if (serverLower.contains("jetty")) techs.add("Jetty");
            if (serverLower.contains("php")) techs.add("PHP");
            if (serverLower.contains("asp")) techs.add("ASP.NET");
        }
        
        String poweredBy = context.getPoweredBy();
        if (poweredBy != null) {
            String poweredByLower = poweredBy.toLowerCase();
            if (poweredByLower.contains("php")) techs.add("PHP");
            if (poweredByLower.contains("asp")) techs.add("ASP.NET");
            if (poweredByLower.contains("express")) techs.add("Express");
            if (poweredByLower.contains("django")) techs.add("Django");
            if (poweredByLower.contains("flask")) techs.add("Flask");
            if (poweredByLower.contains("spring")) techs.add("Spring");
            if (poweredByLower.contains("laravel")) techs.add("Laravel");
            if (poweredByLower.contains("rails")) techs.add("Rails");
        }
        
        String path = context.getPath();
        if (path != null) {
            String pathLower = path.toLowerCase();
            if (pathLower.contains(".php")) techs.add("PHP");
            if (pathLower.contains(".asp")) techs.add("ASP");
            if (pathLower.contains(".aspx")) techs.add("ASP.NET");
            if (pathLower.contains(".jsp")) techs.add("Java/JSP");
            if (pathLower.contains("/api/")) techs.add("REST API");
            if (pathLower.contains("graphql")) techs.add("GraphQL");
        }
        
        String contentType = context.getContentType();
        if (contentType != null) {
            if (contentType.contains("json")) techs.add("JSON API");
            if (contentType.contains("xml")) techs.add("XML");
        }
        
        String requestBody = context.getRequestBody();
        if (requestBody != null) {
            if (requestBody.contains("__VIEWSTATE")) techs.add("ASP.NET ViewState");
            if (requestBody.contains("csrf") || requestBody.contains("_token")) techs.add("CSRF Token");
            if (requestBody.contains("graphql")) techs.add("GraphQL");
        }
        
        String responseBody = context.getResponseBody();
        if (responseBody != null) {
            String bodyLower = responseBody.toLowerCase();
            if (bodyLower.contains("mysql") || bodyLower.contains("mariadb")) techs.add("MySQL");
            if (bodyLower.contains("postgresql")) techs.add("PostgreSQL");
            if (bodyLower.contains("oracle")) techs.add("Oracle");
            if (bodyLower.contains("mssql") || bodyLower.contains("sql server")) techs.add("MSSQL");
            if (bodyLower.contains("mongodb")) techs.add("MongoDB");
            if (bodyLower.contains("redis")) techs.add("Redis");
            if (bodyLower.contains("react")) techs.add("React");
            if (bodyLower.contains("vue")) techs.add("Vue.js");
            if (bodyLower.contains("angular")) techs.add("Angular");
            if (bodyLower.contains("jquery")) techs.add("jQuery");
            if (bodyLower.contains("wordpress")) techs.add("WordPress");
            if (bodyLower.contains("drupal")) techs.add("Drupal");
            if (bodyLower.contains("joomla")) techs.add("Joomla");
            if (bodyLower.contains("discuz")) techs.add("Discuz");
        }
        
        List<String> cookies = context.getCookies();
        if (cookies != null) {
            for (String cookie : cookies) {
                String cookieLower = cookie.toLowerCase();
                if (cookieLower.contains("phpsessid")) techs.add("PHP");
                if (cookieLower.contains("jsessionid")) techs.add("Java");
                if (cookieLower.contains("aspnet")) techs.add("ASP.NET");
                if (cookieLower.contains("laravel")) techs.add("Laravel");
                if (cookieLower.contains("django")) techs.add("Django");
                if (cookieLower.contains("ci_session")) techs.add("CodeIgniter");
                if (cookieLower.contains("laravel_session")) techs.add("Laravel");
            }
        }
        
        context.setTechnologies(techs);
    }
    
    private void detectFrameworks(RequestContext context) {
        Set<String> frontend = new HashSet<>();
        Set<String> backend = new HashSet<>();
        
        String poweredBy = context.getPoweredBy();
        if (poweredBy != null) {
            String poweredByLower = poweredBy.toLowerCase();
            if (poweredByLower.contains("express")) backend.add("Express");
            if (poweredByLower.contains("django")) backend.add("Django");
            if (poweredByLower.contains("flask")) backend.add("Flask");
            if (poweredByLower.contains("spring")) backend.add("Spring");
            if (poweredByLower.contains("laravel")) backend.add("Laravel");
            if (poweredByLower.contains("rails")) backend.add("Rails");
            if (poweredByLower.contains("asp.net")) backend.add("ASP.NET");
            if (poweredByLower.contains("gin")) backend.add("Gin");
            if (poweredByLower.contains("echo")) backend.add("Echo");
        }
        
        String responseBody = context.getResponseBody();
        if (responseBody != null) {
            String bodyLower = responseBody.toLowerCase();
            if (bodyLower.contains("react") || bodyLower.contains("_reactroot") || bodyLower.contains("data-reactroot")) {
                frontend.add("React");
            }
            if (bodyLower.contains("vue") || bodyLower.contains("__vue__") || bodyLower.contains("data-v-")) {
                frontend.add("Vue.js");
            }
            if (bodyLower.contains("ng-version") || bodyLower.contains("ng-app") || bodyLower.contains("angular")) {
                frontend.add("Angular");
            }
            if (bodyLower.contains("jquery") || bodyLower.contains("$(")) {
                frontend.add("jQuery");
            }
            if (bodyLower.contains("next.js") || bodyLower.contains("__next")) {
                frontend.add("Next.js");
            }
            if (bodyLower.contains("nuxt")) {
                frontend.add("Nuxt.js");
            }
            if (bodyLower.contains("svelte")) {
                frontend.add("Svelte");
            }
        }
        
        String path = context.getPath();
        if (path != null) {
            String pathLower = path.toLowerCase();
            if (pathLower.contains("/wp-") || pathLower.contains("/wp-content")) {
                backend.add("WordPress");
            }
            if (pathLower.contains("/sites/default/files")) {
                backend.add("Drupal");
            }
            if (pathLower.contains("/administrator")) {
                backend.add("Joomla");
            }
        }
        
        context.setFrontendFrameworks(frontend);
        context.setBackendFrameworks(backend);
        
        Set<String> allFrameworks = new HashSet<>();
        allFrameworks.addAll(frontend);
        allFrameworks.addAll(backend);
        context.setFrameworks(allFrameworks);
    }
    
    private void detectDatabases(RequestContext context) {
        Set<String> databases = new HashSet<>();
        
        String responseBody = context.getResponseBody();
        if (responseBody != null) {
            String bodyLower = responseBody.toLowerCase();
            if (bodyLower.contains("mysql") || bodyLower.contains("mariadb")) {
                databases.add("MySQL");
            }
            if (bodyLower.contains("postgresql") || bodyLower.contains("psql")) {
                databases.add("PostgreSQL");
            }
            if (bodyLower.contains("oracle") || bodyLower.contains("ora-")) {
                databases.add("Oracle");
            }
            if (bodyLower.contains("mssql") || bodyLower.contains("sql server") || bodyLower.contains("microsoft sql")) {
                databases.add("MSSQL");
            }
            if (bodyLower.contains("mongodb") || bodyLower.contains("mongo")) {
                databases.add("MongoDB");
            }
            if (bodyLower.contains("redis")) {
                databases.add("Redis");
            }
            if (bodyLower.contains("elasticsearch")) {
                databases.add("Elasticsearch");
            }
            if (bodyLower.contains("cassandra")) {
                databases.add("Cassandra");
            }
            if (bodyLower.contains("sqlite")) {
                databases.add("SQLite");
            }
        }
        
        String requestBody = context.getRequestBody();
        if (requestBody != null) {
            String reqBodyLower = requestBody.toLowerCase();
            if (reqBodyLower.contains("$where") || reqBodyLower.contains("$gt") || reqBodyLower.contains("$ne")) {
                databases.add("MongoDB");
            }
        }
        
        context.setDatabases(databases);
    }
    
    private void analyzeSecurityHeaders(IHttpRequestResponse message, RequestContext context) {
        List<String> missingHeaders = new ArrayList<>();
        
        if (message.getResponse() != null) {
            String responseStr = new String(message.getResponse(), StandardCharsets.UTF_8).toLowerCase();
            
            if (!responseStr.contains("x-frame-options:")) {
                missingHeaders.add("X-Frame-Options");
            }
            if (!responseStr.contains("x-content-type-options:")) {
                missingHeaders.add("X-Content-Type-Options");
            }
            if (!responseStr.contains("x-xss-protection:")) {
                missingHeaders.add("X-XSS-Protection");
            }
            if (!responseStr.contains("strict-transport-security:")) {
                missingHeaders.add("Strict-Transport-Security");
            }
            if (!responseStr.contains("content-security-policy:")) {
                missingHeaders.add("Content-Security-Policy");
            }
            if (!responseStr.contains("x-permitted-cross-domain-policies:")) {
                missingHeaders.add("X-Permitted-Cross-Domain-Policies");
            }
            if (!responseStr.contains("referrer-policy:")) {
                missingHeaders.add("Referrer-Policy");
            }
            if (!responseStr.contains("feature-policy:") && !responseStr.contains("permissions-policy:")) {
                missingHeaders.add("Feature-Policy/Permissions-Policy");
            }
        }
        
        context.setMissingSecurityHeaders(missingHeaders);
    }
    
    public String buildContextPrompt(RequestContext context, String targetParam, String vulnType) {
        StringBuilder prompt = new StringBuilder();
        
        prompt.append("根据以下HTTP请求上下文信息，生成针对性的渗透测试Payload：\n\n");
        
        if (context.getMethod() != null) {
            prompt.append("**请求方法**: ").append(context.getMethod()).append("\n");
        }
        
        if (context.getPath() != null) {
            prompt.append("**请求路径**: ").append(context.getPath()).append("\n");
        }
        
        if (targetParam != null && !targetParam.isEmpty()) {
            prompt.append("**目标参数**: ").append(targetParam).append("\n");
        }
        
        if (context.getContentType() != null) {
            prompt.append("**Content-Type**: ").append(context.getContentType()).append("\n");
        }
        
        if (context.getServerHeader() != null) {
            prompt.append("**服务器**: ").append(context.getServerHeader()).append("\n");
        }
        
        if (context.getPoweredBy() != null) {
            prompt.append("**X-Powered-By**: ").append(context.getPoweredBy()).append("\n");
        }
        
        if (context.getTechnologies() != null && !context.getTechnologies().isEmpty()) {
            prompt.append("**检测到的技术栈**: ").append(String.join(", ", context.getTechnologies())).append("\n");
        }
        
        if (context.getFrameworks() != null && !context.getFrameworks().isEmpty()) {
            prompt.append("**检测到的框架**: ").append(String.join(", ", context.getFrameworks())).append("\n");
        }
        
        if (context.getDatabases() != null && !context.getDatabases().isEmpty()) {
            prompt.append("**检测到的数据库**: ").append(String.join(", ", context.getDatabases())).append("\n");
        }
        
        if (context.getRequestBody() != null && context.getRequestBody().length() < 500) {
            prompt.append("\n**请求体**:\n```\n").append(context.getRequestBody()).append("\n```\n");
        }
        
        if (context.getResponseBody() != null && context.getResponseBody().length() < 500) {
            prompt.append("\n**响应片段**:\n```\n").append(context.getResponseBody()).append("\n```\n");
        }
        
        prompt.append("\n**漏洞类型**: ").append(vulnType != null ? vulnType : "通用").append("\n\n");
        
        prompt.append("请根据以上信息生成100个针对性的测试Payload：\n");
        prompt.append("1. 每行一个payload\n");
        prompt.append("2. 不要包含任何解释性文字\n");
        prompt.append("3. 根据检测到的技术栈针对性优化\n");
        prompt.append("4. 考虑可能的绕过技巧\n");
        prompt.append("5. 按照有效性排序\n");
        
        return prompt.toString();
    }
    
    public String suggestVulnType(RequestContext context) {
        String path = context.getPath();
        String contentType = context.getContentType();
        Set<String> techs = context.getTechnologies();
        Set<String> dbs = context.getDatabases();
        
        if (path != null) {
            String pathLower = path.toLowerCase();
            if (pathLower.contains("upload") || pathLower.contains("file")) {
                return "文件上传";
            }
            if (pathLower.contains("login") || pathLower.contains("auth")) {
                return "认证绕过";
            }
            if (pathLower.contains("search") || pathLower.contains("query")) {
                return "SQL注入";
            }
            if (pathLower.contains("redirect") || pathLower.contains("url")) {
                return "SSRF/开放重定向";
            }
            if (pathLower.contains("export") || pathLower.contains("download")) {
                return "路径遍历";
            }
            if (pathLower.contains("graphql")) {
                return "GraphQL注入";
            }
            if (pathLower.contains("api/") || pathLower.contains("/api")) {
                return "API安全测试";
            }
        }
        
        if (contentType != null && contentType.contains("xml")) {
            return "XXE";
        }
        
        if (contentType != null && contentType.contains("json")) {
            if (dbs != null && (dbs.contains("MongoDB") || dbs.contains("Redis"))) {
                return "NoSQL注入";
            }
            return "SQL注入/XSS";
        }
        
        if (context.getAuthorization() != null && context.getAuthorization().toLowerCase().contains("bearer")) {
            return "JWT认证测试";
        }
        
        if (context.getParameters() != null && !context.getParameters().isEmpty()) {
            return "SQL注入/XSS/命令注入";
        }
        
        return "通用漏洞测试";
    }
}
