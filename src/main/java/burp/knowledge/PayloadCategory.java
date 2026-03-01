package burp.knowledge;

import java.util.List;

public class PayloadCategory {
    
    public static final String SQL_INJECTION = "SQL注入";
    public static final String XSS = "跨站脚本";
    public static final String COMMAND_INJECTION = "命令注入";
    public static final String PATH_TRAVERSAL = "路径遍历";
    public static final String SSRF = "服务端请求伪造";
    public static final String XXE = "XML外部实体";
    public static final String SSTI = "服务端模板注入";
    public static final String DESERIALIZATION = "反序列化";
    public static final String JWT = "JWT安全";
    public static final String NOSQL = "NoSQL注入";
    public static final String LDAP = "LDAP注入";
    public static final String GRAPHQL = "GraphQL注入";
    public static final String AUTH_BYPASS = "认证绕过";
    public static final String WAF_BYPASS = "WAF绕过";
    
    private final String id;
    private final String name;
    private final String description;
    private final List<String> relatedVulnTypes;
    
    public PayloadCategory(String id, String name, String description, List<String> relatedVulnTypes) {
        this.id = id;
        this.name = name;
        this.description = description;
        this.relatedVulnTypes = relatedVulnTypes;
    }
    
    public String getId() { return id; }
    public String getName() { return name; }
    public String getDescription() { return description; }
    public List<String> getRelatedVulnTypes() { return relatedVulnTypes; }
}
