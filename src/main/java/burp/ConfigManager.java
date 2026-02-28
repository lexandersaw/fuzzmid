package burp;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Properties;
import java.util.Map;
import java.util.HashMap;
import java.util.LinkedHashMap;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.DumperOptions;

public class ConfigManager {
    private final IBurpExtenderCallbacks callbacks;
    private final Properties properties;
    private final String CONFIG_DIR_PATH = System.getProperty("user.home") + "/.config/fuzzMind";
    private final String CONFIG_FILE_PATH = CONFIG_DIR_PATH + "/Config.yml";
    private final String BACKUP_FILE_PATH = CONFIG_DIR_PATH + "/Config.yml.bak";
    
    private Map<String, String> promptTemplates = new LinkedHashMap<>();
    private Map<String, String> promptNames = new LinkedHashMap<>();
    
    public static final String API_KEY = "api_key";
    public static final String BASE_URL = "base_url";
    public static final String MODEL = "model";
    public static final String TIMEOUT = "timeout";
    
    private static final String DEFAULT_BASE_URL = "https://api.openai.com/v1/chat/completions";
    private static final String DEFAULT_MODEL = "gpt-3.5-turbo";
    private static final String DEFAULT_TIMEOUT = "60";
    
    public ConfigManager(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.properties = new Properties();
        
        initializeDefaultPrompts();
        
        if (!loadConfigFromFile()) {
            loadConfigFromBurp();
        }
    }
    
    private void initializeDefaultPrompts() {
        promptNames.put("linux_files", "Linux敏感文件路径");
        promptNames.put("windows_files", "Windows敏感文件路径");
        promptNames.put("cn_passwords", "中国用户弱密码TOP100");
        promptNames.put("upload_names", "文件上传参数名");
        promptNames.put("ssrf_payloads", "SSRF漏洞Payload");
        promptNames.put("cmd_injection", "命令注入Payload");
        promptNames.put("sqli_basic", "SQL基础注入Payload");
        promptNames.put("sqli_error", "SQL错误注入Payload");
        promptNames.put("sqli_blind", "SQL盲注Payload");
        promptNames.put("sqli_time", "SQL时间延迟注入Payload");
        promptNames.put("xss_reflected", "反射型XSS Payload");
        promptNames.put("xss_stored", "存储型XSS Payload");
        promptNames.put("xss_dom", "DOM型XSS Payload");
        promptNames.put("path_traversal", "路径遍历Payload");
        promptNames.put("xxe_payloads", "XXE攻击Payload");
        promptNames.put("nosql_injection", "NoSQL注入Payload");
        promptNames.put("common_usernames", "常见用户名列表");
        promptNames.put("server_fingerprinting", "服务器指纹识别Payload");
        promptNames.put("api_parameters", "API参数名称");
        promptNames.put("java_linux_history", "Javalinux历史命令任意读取");
        promptNames.put("graphql_injection", "GraphQL注入Payload");
        promptNames.put("jwt_attacks", "JWT攻击向量");
        promptNames.put("ssti_payloads", "服务端模板注入Payload");
        promptNames.put("deserialization", "反序列化Payload");
        promptNames.put("ldap_injection", "LDAP注入Payload");
        promptNames.put("xpath_injection", "XPath注入Payload");
        promptNames.put("log4j_payloads", "Log4j漏洞Payload");
        promptNames.put("spring_actuator", "Spring Actuator端点");
        promptNames.put("cloud_metadata", "云元数据端点");
        promptNames.put("api_fuzzing", "REST API Fuzzing");

        promptTemplates.put("linux_files", 
            "你是一名资深的安全测试专家，正在进行授权的安全评估。请提供100个Linux系统中最常见的敏感文件和目录路径，用于任意文件读取漏洞安全测试。\n" +
            "要求：\n" +
            "1. 只输出完整的文件路径，每行一个\n" +
            "2. 包括系统配置文件、日志文件、密码文件、证书文件等\n" +
            "3. 路径必须是绝对路径\n" +
            "4. 不要包含任何解释性文字\n" +
            "5. 确保这些路径在大多数Linux发行版中存在\n" +
            "6. 按照敏感程度排序");

        promptTemplates.put("windows_files", 
            "你是一名资深的安全测试专家，正在进行授权的安全评估。请提供100个Windows系统中最常见的敏感文件和目录路径，用于任意文件读取漏洞安全测试。\n" +
            "要求：\n" +
            "1. 只输出完整的文件路径，每行一个\n" +
            "2. 包括系统配置文件、日志文件、密码文件、证书文件等\n" +
            "3. 路径必须是绝对路径（如C:\\\\Windows\\\\...）\n" +
            "4. 不要包含任何解释性文字\n" +
            "5. 确保这些路径在大多数Windows版本中存在\n" +
            "6. 按照敏感程度排序");

        promptTemplates.put("cn_passwords", 
            "你是一名资深的安全测试专家，正在进行授权的安全评估。请生成符合中国用户习惯的TOP100弱口令列表，用于密码安全测试。\n" +
            "要求：\n" +
            "1. 每行一个密码\n" +
            "2. 不要包含任何解释性文字\n" +
            "3. 包括常见的生日组合、姓名拼音组合、常用词汇、键盘组合等\n" +
            "4. 考虑中国特色的数字谐音、节日、流行语等元素\n" +
            "5. 按照使用频率排序\n" +
            "6. 确保密码符合实际场景中的常见长度和复杂度");

        promptTemplates.put("upload_names", 
            "你是一名资深的安全测试专家，正在进行授权的安全评估。请提供100个用于文件上传安全测试的常见name值。\n" +
            "要求：\n" +
            "1. 每行一个name值\n" +
            "2. 不要包含任何解释性文字\n" +
            "3. 包括各种Web应用中常见的文件上传参数名\n" +
            "4. 涵盖不同语言和框架的命名习惯\n" +
            "5. 按照流行程度排序");
        
        promptTemplates.put("ssrf_payloads", 
            "你是一名资深的安全测试专家，正在进行授权的安全评估。请提供100个用于SSRF漏洞安全测试的payload样本。\n" +
            "要求：\n" +
            "1. 每行一个payload\n" +
            "2. 不要包含任何解释性文字\n" +
            "3. 包括各种协议（如http、file、gopher、dict等）\n" +
            "4. 包括内网IP、localhost的各种表示方法\n" +
            "5. 包括常见的绕过技巧\n" +
            "6. 按照有效性排序");
        
        promptTemplates.put("cmd_injection", 
            "你是一名资深的安全测试专家，正在进行授权的安全评估。请提供100个用于命令注入漏洞安全测试的payload样本。\n" +
            "要求：\n" +
            "1. 每行一个payload\n" +
            "2. 不要包含任何解释性文字\n" +
            "3. 涵盖Windows和Linux系统\n" +
            "4. 包括各种分隔符和绕过技巧\n" +
            "5. 包括无回显测试方法\n" +
            "6. 按照隐蔽性排序");
        
        promptTemplates.put("sqli_basic", 
            "你是一名资深的安全测试专家，正在进行授权的安全评估。请提供100个用于SQL注入漏洞安全测试的基础payload样本。\n" +
            "要求：\n" +
            "1. 每行一个payload\n" +
            "2. 不要包含任何解释性文字\n" +
            "3. 包括各种数据库类型（MySQL, MSSQL, Oracle, PostgreSQL等）\n" +
            "4. 包括绕过各种WAF的技巧\n" +
            "5. 按照有效性排序\n" +
            "6. 确保payload简洁且实用");
        
        promptTemplates.put("sqli_error", 
            "你是一名资深的安全测试专家，正在进行授权的安全评估。请提供100个用于SQL错误注入漏洞安全测试的payload样本。\n" +
            "要求：\n" +
            "1. 每行一个payload\n" +
            "2. 不要包含任何解释性文字\n" +
            "3. 包括各种数据库类型的错误触发语句\n" +
            "4. 包括能引发详细错误信息的技巧\n" +
            "5. 按照可靠性排序\n" +
            "6. 确保payload在目标出错时能返回有用信息");

        promptTemplates.put("sqli_blind", 
            "你是一名资深的安全测试专家，正在进行授权的安全评估。请提供100个用于SQL盲注漏洞安全测试的payload样本。\n" +
            "要求：\n" +
            "1. 每行一个payload\n" +
            "2. 不要包含任何解释性文字\n" +
            "3. 包括布尔型盲注和时间型盲注的payload\n" +
            "4. 包括各种数据库类型的盲注技巧\n" +
            "5. 按照可靠性排序\n" +
            "6. 确保payload在无回显情况下有效");

        promptTemplates.put("sqli_time", 
            "你是一名资深的安全测试专家，正在进行授权的安全评估。请提供100个用于SQL时间延迟注入漏洞安全测试的payload样本。\n" +
            "要求：\n" +
            "1. 每行一个payload\n" +
            "2. 不要包含任何解释性文字\n" +
            "3. 包括各种数据库的延时函数\n" +
            "4. 包括不同延时长度的变体\n" +
            "5. 按照适用范围排序\n" +
            "6. 确保payload在各种环境中都能产生明显延时");
        
        promptTemplates.put("xss_reflected", 
            "你是一名资深的安全测试专家，正在进行授权的安全评估。请提供100个用于反射型XSS漏洞安全测试的payload样本。\n" +
            "要求：\n" +
            "1. 每行一个payload\n" +
            "2. 不要包含任何解释性文字\n" +
            "3. 包括绕过各种XSS过滤器的技巧\n" +
            "4. 包括各种事件处理程序（如onclick, onload, onerror等）\n" +
            "5. 按照隐蔽性和有效性排序\n" +
            "6. 确保payload在现代浏览器中有效");

        promptTemplates.put("xss_stored", 
            "你是一名资深的安全测试专家，正在进行授权的安全评估。请提供100个用于存储型XSS漏洞安全测试的payload样本。\n" +
            "要求：\n" +
            "1. 每行一个payload\n" +
            "2. 不要包含任何解释性文字\n" +
            "3. 包括绕过各种存储安全限制的技巧\n" +
            "4. 包括不同的触发方式\n" +
            "5. 按照持久性和有效性排序\n" +
            "6. 确保payload能在数据库存储后仍然有效");

        promptTemplates.put("xss_dom", 
            "你是一名资深的安全测试专家，正在进行授权的安全评估。请提供100个用于DOM型XSS漏洞安全测试的payload样本。\n" +
            "要求：\n" +
            "1. 每行一个payload\n" +
            "2. 不要包含任何解释性文字\n" +
            "3. 包括针对不同DOM方法和属性的payload\n" +
            "4. 包括针对现代前端框架的DOM XSS向量\n" +
            "5. 按照浏览器兼容性排序\n" +
            "6. 确保payload能够在客户端JavaScript执行中触发");
        
        promptTemplates.put("path_traversal", 
            "你是一名资深的安全测试专家，正在进行授权的安全评估。请提供100个用于目录遍历漏洞安全测试的payload样本。\n" +
            "要求：\n" +
            "1. 每行一个payload\n" +
            "2. 不要包含任何解释性文字\n" +
            "3. 包括各种编码方式（如URL编码、双重编码等）\n" +
            "4. 包括绕过各种路径限制的技巧\n" +
            "5. 同时涵盖Windows和Linux/Unix系统\n" +
            "6. 按照绕过能力排序");

        promptTemplates.put("xxe_payloads", 
            "你是一名资深的安全测试专家，正在进行授权的安全评估。请提供100个用于XXE漏洞安全测试的payload样本。\n" +
            "要求：\n" +
            "1. 每行一个payload\n" +
            "2. 不要包含任何解释性文字\n" +
            "3. 包括文件读取、服务器端请求伪造等各种测试向量\n" +
            "4. 包括绕过各种XXE保护机制的技巧\n" +
            "5. 按照有效性排序\n" +
            "6. 确保payload格式正确且实用");

        promptTemplates.put("nosql_injection", 
            "你是一名资深的安全测试专家，正在进行授权的安全评估。请提供100个用于NoSQL注入漏洞安全测试的payload样本。\n" +
            "要求：\n" +
            "1. 每行一个payload\n" +
            "2. 不要包含任何解释性文字\n" +
            "3. 主要针对MongoDB, Redis, Cassandra等常见NoSQL数据库\n" +
            "4. 包括查询操作符和绕过技巧\n" +
            "5. 按照有效性排序\n" +
            "6. 包括JSON格式和URL参数格式");
        
        promptTemplates.put("common_usernames", 
            "你是一名资深的安全测试专家，正在进行授权的安全评估。请提供100个最常见的用户名，用于账号安全测试。\n" +
            "要求：\n" +
            "1. 每行一个用户名\n" +
            "2. 不要包含任何解释性文字\n" +
            "3. 包括常见系统账号（如admin, root, guest等）\n" +
            "4. 包括常见的人名用户名\n" +
            "5. 按照使用频率排序\n" +
            "6. 同时考虑中文和西方环境下的常见用户名");

        promptTemplates.put("server_fingerprinting", 
            "你是一名资深的安全测试专家，正在进行授权的安全评估。请提供100个用于服务器指纹识别的路径和文件。\n" +
            "要求：\n" +
            "1. 每行一个路径或文件名\n" +
            "2. 不要包含任何解释性文字\n" +
            "3. 包括各种Web服务器（Apache, Nginx, IIS等）的特征文件\n" +
            "4. 包括各种Web应用框架（PHP, Django, Rails等）的特征文件\n" +
            "5. 按照特征明显程度排序\n" +
            "6. 路径应该是从网站根目录开始的相对路径");

        promptTemplates.put("api_parameters", 
            "你是一名资深的安全测试专家，正在进行授权的安全评估。请提供100个常见的API参数名称，用于API安全测试。\n" +
            "要求：\n" +
            "1. 每行一个参数名\n" +
            "2. 不要包含任何解释性文字\n" +
            "3. 包括认证、授权相关的参数\n" +
            "4. 包括数据操作相关的参数\n" +
            "5. 包括常见的过滤和排序参数\n" +
            "6. 按照使用频率排序");

        promptTemplates.put("java_linux_history", 
            "你是一名资深的安全测试专家，正在进行授权的安全评估。请根据以下某linux下的java系统存在文件读取漏洞的数据包，结合bash_history的内容分析，提供100个常见的后渗透读取信息，用于深入安全测试\n" +
            "要求：\n" +
            "1. 只输出完整的文件路径如数据包中的/root/.bash_history，每行一个\n" +
            "2. 包括系统配置文件、源代码等\n" +
            "3. 不要包含任何解释性文字\n" +
            "4. 确保这些路径在大多数linux下javaweb中存在\n" +
            "5. 按照敏感程度排序\n" +
            "数据包如下：\n");

        promptTemplates.put("graphql_injection",
            "你是一名资深的安全测试专家，正在进行授权的安全评估。请提供100个用于GraphQL注入安全测试的payload样本。\n" +
            "要求：\n" +
            "1. 每行一个payload\n" +
            "2. 不要包含任何解释性文字\n" +
            "3. 包括GraphQL内省查询、字段混淆、批量查询攻击等\n" +
            "4. 包括各种绕过认证和授权的技巧\n" +
            "5. 按照有效性排序\n" +
            "6. 确保payload适用于主流GraphQL实现");

        promptTemplates.put("jwt_attacks",
            "你是一名资深的安全测试专家，正在进行授权的安全评估。请提供100个用于JWT安全漏洞测试的payload样本。\n" +
            "要求：\n" +
            "1. 每行一个payload或攻击向量\n" +
            "2. 不要包含任何解释性文字\n" +
            "3. 包括none算法攻击、弱密钥爆破、kid注入等\n" +
            "4. 包括header和payload的各种修改技巧\n" +
            "5. 按照有效性排序\n" +
            "6. 适用于实际渗透测试场景");

        promptTemplates.put("ssti_payloads",
            "你是一名资深的安全测试专家，正在进行授权的安全评估。请提供100个用于服务端模板注入(SSTI)安全测试的payload样本。\n" +
            "要求：\n" +
            "1. 每行一个payload\n" +
            "2. 不要包含任何解释性文字\n" +
            "3. 包括Jinja2、Twig、Freemarker、Velocity等模板引擎\n" +
            "4. 包括各种沙箱绕过技巧\n" +
            "5. 按照有效性排序\n" +
            "6. 确保payload能触发代码执行或信息泄露");

        promptTemplates.put("deserialization",
            "你是一名资深的安全测试专家，正在进行授权的安全评估。请提供100个用于反序列化漏洞安全测试的payload样本。\n" +
            "要求：\n" +
            "1. 每行一个payload\n" +
            "2. 不要包含任何解释性文字\n" +
            "3. 包括Java、PHP、Python、.NET等语言的反序列化payload\n" +
            "4. 包括各种Gadget链和利用技巧\n" +
            "5. 按照有效性排序\n" +
            "6. 确保payload格式正确");

        promptTemplates.put("ldap_injection",
            "你是一名资深的安全测试专家，正在进行授权的安全评估。请提供100个用于LDAP注入漏洞安全测试的payload样本。\n" +
            "要求：\n" +
            "1. 每行一个payload\n" +
            "2. 不要包含任何解释性文字\n" +
            "3. 包括各种LDAP过滤器的注入技巧\n" +
            "4. 包括认证绕过和信息泄露payload\n" +
            "5. 按照有效性排序\n" +
            "6. 确保payload适用于Active Directory和OpenLDAP");

        promptTemplates.put("xpath_injection",
            "你是一名资深的安全测试专家，正在进行授权的安全评估。请提供100个用于XPath注入漏洞安全测试的payload样本。\n" +
            "要求：\n" +
            "1. 每行一个payload\n" +
            "2. 不要包含任何解释性文字\n" +
            "3. 包括各种XPath表达式的注入技巧\n" +
            "4. 包括布尔盲注和绕过技巧\n" +
            "5. 按照有效性排序\n" +
            "6. 确保payload能绕过常见过滤");

        promptTemplates.put("log4j_payloads",
            "你是一名资深的安全测试专家，正在进行授权的安全评估。请提供100个用于Log4j漏洞(Log4Shell)安全测试的payload样本。\n" +
            "要求：\n" +
            "1. 每行一个payload\n" +
            "2. 不要包含任何解释性文字\n" +
            "3. 包括各种JNDI注入变体\n" +
            "4. 包括各种绕过WAF的技巧（编码、分块等）\n" +
            "5. 按照有效性排序\n" +
            "6. 确保payload能触发DNS回调或HTTP请求");

        promptTemplates.put("spring_actuator",
            "你是一名资深的安全测试专家，正在进行授权的安全评估。请提供100个用于Spring Boot Actuator安全测试的端点和payload。\n" +
            "要求：\n" +
            "1. 每行一个端点路径或payload\n" +
            "2. 不要包含任何解释性文字\n" +
            "3. 包括各种敏感端点（env、heapdump、mappings等）\n" +
            "4. 包括端点利用技巧\n" +
            "5. 按照敏感程度排序\n" +
            "6. 确保适用于Spring Boot 1.x和2.x版本");

        promptTemplates.put("cloud_metadata",
            "你是一名资深的安全测试专家，正在进行授权的安全评估。请提供100个用于云元数据服务安全测试的端点。\n" +
            "要求：\n" +
            "1. 每行一个端点URL\n" +
            "2. 不要包含任何解释性文字\n" +
            "3. 包括AWS、Azure、GCP、阿里云等云厂商的元数据端点\n" +
            "4. 包括敏感信息获取路径\n" +
            "5. 按照敏感程度排序\n" +
            "6. 确保端点URL格式正确");

        promptTemplates.put("api_fuzzing",
            "你是一名资深的安全测试专家，正在进行授权的安全评估。请提供100个用于REST API Fuzzing测试的payload样本。\n" +
            "要求：\n" +
            "1. 每行一个payload或测试向量\n" +
            "2. 不要包含任何解释性文字\n" +
            "3. 包括各种HTTP方法测试、参数污染、格式注入等\n" +
            "4. 包括IDOR、批量请求等API安全测试技巧\n" +
            "5. 按照有效性排序\n" +
            "6. 适用于RESTful API安全测试");
    }
    
    private boolean loadConfigFromFile() {
        try {
            File configDir = new File(CONFIG_DIR_PATH);
            File configFile = new File(CONFIG_FILE_PATH);
            
            if (!configFile.exists()) {
                if (!configDir.exists()) {
                    configDir.mkdirs();
                }
                saveConfigToFile();
                return true;
            }
            
            String content = new String(Files.readAllBytes(Paths.get(CONFIG_FILE_PATH)), StandardCharsets.UTF_8);
            
            if (content == null || content.trim().isEmpty()) {
                callbacks.printError("Config file is empty, creating default config");
                return restoreFromBackup() || createDefaultConfig();
            }
            
            Yaml yaml = new Yaml();
            Map<String, Object> config = yaml.load(content);
            
            if (config == null) {
                callbacks.printError("Config file parse result is null");
                return restoreFromBackup() || createDefaultConfig();
            }
            
            if (config.containsKey("api")) {
                Object apiObj = config.get("api");
                if (apiObj instanceof Map) {
                    @SuppressWarnings("unchecked")
                    Map<String, Object> apiConfig = (Map<String, Object>) apiObj;
                    if (apiConfig.containsKey("api_key")) {
                        properties.setProperty(API_KEY, String.valueOf(apiConfig.get("api_key")));
                    }
                    if (apiConfig.containsKey("base_url")) {
                        properties.setProperty(BASE_URL, String.valueOf(apiConfig.get("base_url")));
                    } else {
                        properties.setProperty(BASE_URL, DEFAULT_BASE_URL);
                    }
                    if (apiConfig.containsKey("model")) {
                        properties.setProperty(MODEL, String.valueOf(apiConfig.get("model")));
                    } else {
                        properties.setProperty(MODEL, DEFAULT_MODEL);
                    }
                    if (apiConfig.containsKey("timeout")) {
                        properties.setProperty(TIMEOUT, String.valueOf(apiConfig.get("timeout")));
                    } else {
                        properties.setProperty(TIMEOUT, DEFAULT_TIMEOUT);
                    }
                }
            } else {
                properties.setProperty(BASE_URL, DEFAULT_BASE_URL);
                properties.setProperty(MODEL, DEFAULT_MODEL);
                properties.setProperty(TIMEOUT, DEFAULT_TIMEOUT);
            }
            
            if (config.containsKey("prompt_names")) {
                Object namesObj = config.get("prompt_names");
                if (namesObj instanceof Map) {
                    @SuppressWarnings("unchecked")
                    Map<String, Object> names = (Map<String, Object>) namesObj;
                    for (Map.Entry<String, Object> entry : names.entrySet()) {
                        promptNames.put(entry.getKey(), String.valueOf(entry.getValue()));
                    }
                }
            }
            
            if (config.containsKey("prompt_templates")) {
                Object templatesObj = config.get("prompt_templates");
                if (templatesObj instanceof Map) {
                    @SuppressWarnings("unchecked")
                    Map<String, Object> templates = (Map<String, Object>) templatesObj;
                    for (Map.Entry<String, Object> entry : templates.entrySet()) {
                        promptTemplates.put(entry.getKey(), String.valueOf(entry.getValue()));
                    }
                }
            }
            
            return true;
            
        } catch (Exception e) {
            callbacks.printError("Failed to load config file: " + e.getMessage());
            return restoreFromBackup() || createDefaultConfig();
        }
    }
    
    private boolean restoreFromBackup() {
        try {
            File backupFile = new File(BACKUP_FILE_PATH);
            if (!backupFile.exists()) {
                return false;
            }
            
            Files.copy(Paths.get(BACKUP_FILE_PATH), Paths.get(CONFIG_FILE_PATH));
            callbacks.printOutput("Restored config from backup");
            return loadConfigFromFile();
        } catch (Exception e) {
            callbacks.printError("Failed to restore from backup: " + e.getMessage());
            return false;
        }
    }
    
    private boolean createDefaultConfig() {
        try {
            properties.setProperty(BASE_URL, DEFAULT_BASE_URL);
            properties.setProperty(MODEL, DEFAULT_MODEL);
            properties.setProperty(TIMEOUT, DEFAULT_TIMEOUT);
            saveConfigToFile();
            return true;
        } catch (Exception e) {
            callbacks.printError("Failed to create default config: " + e.getMessage());
            return false;
        }
    }
    
    private void loadConfigFromBurp() {
        String apiKey = callbacks.loadExtensionSetting(API_KEY);
        String baseUrl = callbacks.loadExtensionSetting(BASE_URL);
        String model = callbacks.loadExtensionSetting(MODEL);
        
        if (apiKey != null) properties.setProperty(API_KEY, apiKey);
        if (baseUrl != null) properties.setProperty(BASE_URL, baseUrl);
        if (model != null) properties.setProperty(MODEL, model);
    }
    
    public void saveConfig(String apiKey, String baseUrl, String model) {
        properties.setProperty(API_KEY, apiKey != null ? apiKey : "");
        properties.setProperty(BASE_URL, baseUrl != null ? baseUrl : DEFAULT_BASE_URL);
        properties.setProperty(MODEL, model != null ? model : DEFAULT_MODEL);
        saveConfigToFile();
        
        callbacks.saveExtensionSetting(API_KEY, apiKey);
        callbacks.saveExtensionSetting(BASE_URL, baseUrl);
        callbacks.saveExtensionSetting(MODEL, model);
    }
    
    public void saveConfig(String apiKey, String baseUrl, String model, String timeout) {
        properties.setProperty(API_KEY, apiKey != null ? apiKey : "");
        properties.setProperty(BASE_URL, baseUrl != null ? baseUrl : DEFAULT_BASE_URL);
        properties.setProperty(MODEL, model != null ? model : DEFAULT_MODEL);
        properties.setProperty(TIMEOUT, timeout != null ? timeout : DEFAULT_TIMEOUT);
        saveConfigToFile();
        
        callbacks.saveExtensionSetting(API_KEY, apiKey);
        callbacks.saveExtensionSetting(BASE_URL, baseUrl);
        callbacks.saveExtensionSetting(MODEL, model);
        callbacks.saveExtensionSetting(TIMEOUT, timeout);
    }
    
    private void saveConfigToFile() {
        try {
            File configDir = new File(CONFIG_DIR_PATH);
            if (!configDir.exists()) {
                configDir.mkdirs();
            }
            
            File backupFile = new File(BACKUP_FILE_PATH);
            File configFile = new File(CONFIG_FILE_PATH);
            if (configFile.exists()) {
                Files.copy(Paths.get(CONFIG_FILE_PATH), Paths.get(BACKUP_FILE_PATH));
            }
            
            DumperOptions options = new DumperOptions();
            options.setDefaultFlowStyle(DumperOptions.FlowStyle.BLOCK);
            options.setPrettyFlow(true);
            Yaml yaml = new Yaml(options);
            
            Map<String, Object> config = new LinkedHashMap<>();
            
            Map<String, String> apiConfig = new LinkedHashMap<>();
            apiConfig.put("api_key", properties.getProperty(API_KEY, ""));
            apiConfig.put("base_url", properties.getProperty(BASE_URL, DEFAULT_BASE_URL));
            apiConfig.put("model", properties.getProperty(MODEL, DEFAULT_MODEL));
            apiConfig.put("timeout", properties.getProperty(TIMEOUT, DEFAULT_TIMEOUT));
            config.put("api", apiConfig);
            
            config.put("prompt_names", new LinkedHashMap<>(promptNames));
            config.put("prompt_templates", new LinkedHashMap<>(promptTemplates));
            
            String yamlContent = yaml.dump(config);
            Files.write(Paths.get(CONFIG_FILE_PATH), yamlContent.getBytes(StandardCharsets.UTF_8));
            
        } catch (Exception e) {
            callbacks.printError("Failed to save config file: " + e.getMessage());
        }
    }
    
    public String getConfig(String key) {
        return properties.getProperty(key);
    }
    
    public String getConfig(String key, String defaultValue) {
        return properties.getProperty(key, defaultValue);
    }
    
    public void setConfig(String key, String value) {
        properties.setProperty(key, value);
    }
    
    public Map<String, String> getPromptTemplates() {
        return new LinkedHashMap<>(promptTemplates);
    }
    
    public Map<String, String> getPromptNames() {
        return new LinkedHashMap<>(promptNames);
    }
    
    public String getPromptTemplate(String type) {
        return promptTemplates.get(type);
    }
    
    public String getPromptName(String type) {
        return promptNames.get(type);
    }
    
    public void addPromptTemplate(String type, String name, String template) {
        promptNames.put(type, name);
        promptTemplates.put(type, template);
        saveConfigToFile();
    }
    
    public void addPromptType(String type, String name, String template) {
        promptNames.put(type, name);
        promptTemplates.put(type, template);
        saveConfigToFile();
    }
    
    public void removePromptTemplate(String type) {
        promptNames.remove(type);
        promptTemplates.remove(type);
        saveConfigToFile();
    }
    
    public void removePromptType(String type) {
        promptNames.remove(type);
        promptTemplates.remove(type);
        saveConfigToFile();
    }
    
    public void updatePromptTemplate(String type, String template) {
        if (promptTemplates.containsKey(type)) {
            promptTemplates.put(type, template);
            saveConfigToFile();
        }
    }
    
    public void updatePromptType(String type, String name, String template) {
        promptNames.put(type, name);
        promptTemplates.put(type, template);
        saveConfigToFile();
    }
    
    public java.util.Set<String> getPromptTypes() {
        return promptTemplates.keySet();
    }
    
    public void setPromptTemplate(String type, String template) {
        promptTemplates.put(type, template);
        saveConfigToFile();
    }
    
    public boolean hasApiKey() {
        String apiKey = getConfig(API_KEY);
        return apiKey != null && !apiKey.trim().isEmpty();
    }
}
