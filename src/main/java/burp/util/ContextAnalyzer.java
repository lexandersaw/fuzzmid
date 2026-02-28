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
    }
    
    public RequestContext analyzeRequest(IHttpRequestResponse message) {
        RequestContext context = new RequestContext();
        
        if (message == null || message.getRequest() == null) {
            return context;
        }
        
        byte[] request = message.getRequest();
        
        try {
            analyzeHttpMethod(request, context);
            analyzeUrl(request, context);
            analyzeHeaders(request, context);
            analyzeParameters(request, context);
            analyzeBody(request, context);
            analyzeResponse(message, context);
            detectTechnologies(context);
        } catch (Exception e) {
            e.printStackTrace();
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
    }
    
    private void analyzeHeaders(byte[] request, RequestContext context) {
        String requestStr = new String(request, StandardCharsets.UTF_8);
        
        Pattern contentTypePattern = Pattern.compile("Content-Type:\\s*([^\\r\\n]+)", Pattern.CASE_INSENSITIVE);
        Matcher ctMatcher = contentTypePattern.matcher(requestStr);
        if (ctMatcher.find()) {
            context.setContentType(ctMatcher.group(1).trim());
        }
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
        }
    }
    
    private void detectTechnologies(RequestContext context) {
        Set<String> techs = new HashSet<>();
        
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
        
        String path = context.getPath();
        if (path != null) {
            String pathLower = path.toLowerCase();
            if (pathLower.contains(".php")) techs.add("PHP");
            if (pathLower.contains(".asp")) techs.add("ASP");
            if (pathLower.contains(".aspx")) techs.add("ASP.NET");
            if (pathLower.contains(".jsp")) techs.add("Java/JSP");
            if (pathLower.contains("/api/")) techs.add("REST API");
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
        }
        
        context.setTechnologies(techs);
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
        
        if (context.getTechnologies() != null && !context.getTechnologies().isEmpty()) {
            prompt.append("**检测到的技术栈**: ").append(String.join(", ", context.getTechnologies())).append("\n");
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
        }
        
        if (contentType != null && contentType.contains("xml")) {
            return "XXE";
        }
        
        if (contentType != null && contentType.contains("json")) {
            if (techs.contains("MongoDB") || techs.contains("Redis")) {
                return "NoSQL注入";
            }
            return "SQL注入/XSS";
        }
        
        if (context.getParameters() != null && !context.getParameters().isEmpty()) {
            return "SQL注入/XSS/命令注入";
        }
        
        return "通用漏洞测试";
    }
}
