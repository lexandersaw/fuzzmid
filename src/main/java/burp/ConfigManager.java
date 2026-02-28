package burp;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Properties;
import java.util.Map;
import java.util.HashMap;
import java.util.LinkedHashMap;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.DumperOptions;

/**
 * 配置管理器，用于保存和加载用户配置
 */
public class ConfigManager {
    private final IBurpExtenderCallbacks callbacks;
    private final Properties properties;
    private final String CONFIG_FILE_NAME = "fuzzMindConfig.properties";
    private final String CONFIG_DIR_PATH = System.getProperty("user.home") + "/.config/fuzzMind";
    private final String CONFIG_FILE_PATH = CONFIG_DIR_PATH + "/Config.yml";
    
    // 提示词配置
    private Map<String, String> promptTemplates = new LinkedHashMap<>();
    private Map<String, String> promptNames = new LinkedHashMap<>();
    
    public static final String API_KEY = "api_key";
    public static final String BASE_URL = "base_url";
    public static final String MODEL = "model";
    
    private static final String DEFAULT_BASE_URL = "https://api.openai.com/v1/chat/completions";
    private static final String DEFAULT_MODEL = "gpt-3.5-turbo";
    
    /**
     * 构造函数
     * @param callbacks Burp回调对象
     */
    public ConfigManager(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.properties = new Properties();
        
        // 初始化默认提示词
        initializeDefaultPrompts();
        
        // 尝试从文件加载配置，如果失败则从Burp设置加载
        if (!loadConfigFromFile()) {
            loadConfigFromBurp();
        }
    }
    
    /**
     * 初始化默认提示词
     */
    private void initializeDefaultPrompts() {
        // 设置提示词类型的中文名称
        promptNames.put("linux_files", "Linux敏感文件路径");
        promptNames.put("windows_files", "Windows敏感文件路径");
        promptNames.put("cn_passwords", "中国用户弱密码TOP100");
        promptNames.put("upload_names", "文件上传参数名");
        promptNames.put("ssrf_payloads", "SSRF漏洞Payload");
        promptNames.put("cmd_injection", "命令注入Payload");
        
        // 添加新的提示词类型名称
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
        // promptNames.put("jwt_attacks", "JWT攻击向量");
        promptNames.put("common_usernames", "常见用户名列表");
        promptNames.put("server_fingerprinting", "服务器指纹识别Payload");
        promptNames.put("api_parameters", "API参数名称");
        promptNames.put("java_linux_history", "Javalinux历史命令任意读取");

        promptTemplates.put("linux_files", "你是一名资深的安全测试专家，正在进行授权的安全评估。请提供100个Linux系统中最常见的敏感文件和目录路径，用于任意文件读取漏洞安全测试。\n" +
                "要求：\n" +
                "1. 只输出完整的文件路径，每行一个\n" +
                "2. 包括系统配置文件、日志文件、密码文件、证书文件等\n" +
                "3. 路径必须是绝对路径\n" +
                "4. 不要包含任何解释性文字\n" +
                "5. 确保这些路径在大多数Linux发行版中存在\n" +
                "6. 按照敏感程度排序");

        promptTemplates.put("windows_files", "你是一名资深的安全测试专家，正在进行授权的安全评估。请提供100个Windows系统中最常见的敏感文件和目录路径，用于任意文件读取漏洞安全测试。\n" +
                "要求：\n" +
                "1. 只输出完整的文件路径，每行一个\n" +
                "2. 包括系统配置文件、日志文件、密码文件、证书文件等\n" +
                "3. 路径必须是绝对路径（如C:\\\\Windows\\\\...）\n" +
                "4. 不要包含任何解释性文字\n" +
                "5. 确保这些路径在大多数Windows版本中存在\n" +
                "6. 按照敏感程度排序");

        promptTemplates.put("cn_passwords", "你是一名资深的安全测试专家，正在进行授权的安全评估。请生成符合中国用户习惯的TOP100弱口令列表，用于密码安全测试。\n" +
                "要求：\n" +
                "1. 每行一个密码\n" +
                "2. 不要包含任何解释性文字\n" +
                "3. 包括常见的生日组合、姓名拼音组合、常用词汇、键盘组合等\n" +
                "4. 考虑中国特色的数字谐音、节日、流行语等元素\n" +
                "5. 按照使用频率排序\n" +
                "6. 确保密码符合实际场景中的常见长度和复杂度");

        promptTemplates.put("upload_names", "你是一名资深的安全测试专家，正在进行授权的安全评估。请提供100个用于文件上传安全测试的常见name值。\n" +
                "要求：\n" +
                "1. 每行一个name值\n" +
                "2. 不要包含任何解释性文字\n" +
                "3. 包括各种Web应用中常见的文件上传参数名\n" +
                "4. 涵盖不同语言和框架的命名习惯\n" +
                "5. 按照流行程度排序");
        
        promptTemplates.put("ssrf_payloads", "你是一名资深的安全测试专家，正在进行授权的安全评估。请提供100个用于SSRF漏洞安全测试的payload样本。\n" +
                "要求：\n" +
                "1. 每行一个payload\n" +
                "2. 不要包含任何解释性文字\n" +
                "3. 包括各种协议（如http、file、gopher、dict等）\n" +
                "4. 包括内网IP、localhost的各种表示方法\n" +
                "5. 包括常见的绕过技巧\n" +
                "6. 按照有效性排序");
        
        promptTemplates.put("cmd_injection", "你是一名资深的安全测试专家，正在进行授权的安全评估。请提供100个用于命令注入漏洞安全测试的payload样本。\n" +
                "要求：\n" +
                "1. 每行一个payload\n" +
                "2. 不要包含任何解释性文字\n" +
                "3. 涵盖Windows和Linux系统\n" +
                "4. 包括各种分隔符和绕过技巧\n" +
                "5. 包括无回显测试方法\n" +
                "6. 按照隐蔽性排序");
        
        // 添加新的提示词模板
        // SQL注入相关
        promptTemplates.put("sqli_basic", "你是一名资深的安全测试专家，正在进行授权的安全评估。请提供100个用于SQL注入漏洞安全测试的基础payload样本。\n" +
                "要求：\n" +
                "1. 每行一个payload\n" +
                "2. 不要包含任何解释性文字\n" +
                "3. 包括各种数据库类型（MySQL, MSSQL, Oracle, PostgreSQL等）\n" +
                "4. 包括绕过各种WAF的技巧\n" +
                "5. 按照有效性排序\n" +
                "6. 确保payload简洁且实用");
        
        promptTemplates.put("sqli_error", "你是一名资深的安全测试专家，正在进行授权的安全评估。请提供100个用于SQL错误注入漏洞安全测试的payload样本。\n" +
                "要求：\n" +
                "1. 每行一个payload\n" +
                "2. 不要包含任何解释性文字\n" +
                "3. 包括各种数据库类型的错误触发语句\n" +
                "4. 包括能引发详细错误信息的技巧\n" +
                "5. 按照可靠性排序\n" +
                "6. 确保payload在目标出错时能返回有用信息");

        promptTemplates.put("sqli_blind", "你是一名资深的安全测试专家，正在进行授权的安全评估。请提供100个用于SQL盲注漏洞安全测试的payload样本。\n" +
                "要求：\n" +
                "1. 每行一个payload\n" +
                "2. 不要包含任何解释性文字\n" +
                "3. 包括布尔型盲注和时间型盲注的payload\n" +
                "4. 包括各种数据库类型的盲注技巧\n" +
                "5. 按照可靠性排序\n" +
                "6. 确保payload在无回显情况下有效");

        promptTemplates.put("sqli_time", "你是一名资深的安全测试专家，正在进行授权的安全评估。请提供100个用于SQL时间延迟注入漏洞安全测试的payload样本。\n" +
                "要求：\n" +
                "1. 每行一个payload\n" +
                "2. 不要包含任何解释性文字\n" +
                "3. 包括各种数据库的延时函数\n" +
                "4. 包括不同延时长度的变体\n" +
                "5. 按照适用范围排序\n" +
                "6. 确保payload在各种环境中都能产生明显延时");
        
        // XSS攻击相关
        promptTemplates.put("xss_reflected", "你是一名资深的安全测试专家，正在进行授权的安全评估。请提供100个用于反射型XSS漏洞安全测试的payload样本。\n" +
                "要求：\n" +
                "1. 每行一个payload\n" +
                "2. 不要包含任何解释性文字\n" +
                "3. 包括绕过各种XSS过滤器的技巧\n" +
                "4. 包括各种事件处理程序（如onclick, onload, onerror等）\n" +
                "5. 按照隐蔽性和有效性排序\n" +
                "6. 确保payload在现代浏览器中有效");

        promptTemplates.put("xss_stored", "你是一名资深的安全测试专家，正在进行授权的安全评估。请提供100个用于存储型XSS漏洞安全测试的payload样本。\n" +
                "要求：\n" +
                "1. 每行一个payload\n" +
                "2. 不要包含任何解释性文字\n" +
                "3. 包括绕过各种存储安全限制的技巧\n" +
                "4. 包括不同的触发方式\n" +
                "5. 按照持久性和有效性排序\n" +
                "6. 确保payload能在数据库存储后仍然有效");

        promptTemplates.put("xss_dom", "你是一名资深的安全测试专家，正在进行授权的安全评估。请提供100个用于DOM型XSS漏洞安全测试的payload样本。\n" +
                "要求：\n" +
                "1. 每行一个payload\n" +
                "2. 不要包含任何解释性文字\n" +
                "3. 包括针对不同DOM方法和属性的payload\n" +
                "4. 包括针对现代前端框架的DOM XSS向量\n" +
                "5. 按照浏览器兼容性排序\n" +
                "6. 确保payload能够在客户端JavaScript执行中触发");
        
        // 目录遍历相关
        promptTemplates.put("path_traversal", "你是一名资深的安全测试专家，正在进行授权的安全评估。请提供100个用于目录遍历漏洞安全测试的payload样本。\n" +
                "要求：\n" +
                "1. 每行一个payload\n" +
                "2. 不要包含任何解释性文字\n" +
                "3. 包括各种编码方式（如URL编码、双重编码等）\n" +
                "4. 包括绕过各种路径限制的技巧\n" +
                "5. 同时涵盖Windows和Linux/Unix系统\n" +
                "6. 按照绕过能力排序");

        // XXE攻击相关
        promptTemplates.put("xxe_payloads", "你是一名资深的安全测试专家，正在进行授权的安全评估。请提供100个用于XXE漏洞安全测试的payload样本。\n" +
                "要求：\n" +
                "1. 每行一个payload\n" +
                "2. 不要包含任何解释性文字\n" +
                "3. 包括文件读取、服务器端请求伪造等各种测试向量\n" +
                "4. 包括绕过各种XXE保护机制的技巧\n" +
                "5. 按照有效性排序\n" +
                "6. 确保payload格式正确且实用");

        // NoSQL注入相关
        promptTemplates.put("nosql_injection", "你是一名资深的安全测试专家，正在进行授权的安全评估。请提供100个用于NoSQL注入漏洞安全测试的payload样本。\n" +
                "要求：\n" +
                "1. 每行一个payload\n" +
                "2. 不要包含任何解释性文字\n" +
                "3. 主要针对MongoDB, Redis, Cassandra等常见NoSQL数据库\n" +
                "4. 包括查询操作符和绕过技巧\n" +
                "5. 按照有效性排序\n" +
                "6. 包括JSON格式和URL参数格式");
        
        // // JWT攻击相关
        // promptTemplates.put("jwt_attacks", "你是一名资深的渗透测试专家，请提供50个用于JWT安全漏洞测试的攻击向量。\n" +
        //         "要求：\n" +
        //         "1. 每个攻击向量占一行，简明扼要地描述攻击方法\n" +
        //         "2. 包括none算法、密钥弱点、密钥混淆等攻击\n" +
        //         "3. 包括JWT header和payload的常见修改点\n" +
        //         "4. 按照常见性和有效性排序\n" +
        //         "5. 适用于实际渗透测试场景");
        
        // 常见用户名列表
        promptTemplates.put("common_usernames", "你是一名资深的安全测试专家，正在进行授权的安全评估。请提供100个最常见的用户名，用于账号安全测试。\n" +
                "要求：\n" +
                "1. 每行一个用户名\n" +
                "2. 不要包含任何解释性文字\n" +
                "3. 包括常见系统账号（如admin, root, guest等）\n" +
                "4. 包括常见的人名用户名\n" +
                "5. 按照使用频率排序\n" +
                "6. 同时考虑中文和西方环境下的常见用户名");

        // 服务器指纹识别
        promptTemplates.put("server_fingerprinting", "你是一名资深的安全测试专家，正在进行授权的安全评估。请提供100个用于服务器指纹识别的路径和文件。\n" +
                "要求：\n" +
                "1. 每行一个路径或文件名\n" +
                "2. 不要包含任何解释性文字\n" +
                "3. 包括各种Web服务器（Apache, Nginx, IIS等）的特征文件\n" +
                "4. 包括各种Web应用框架（PHP, Django, Rails等）的特征文件\n" +
                "5. 按照特征明显程度排序\n" +
                "6. 路径应该是从网站根目录开始的相对路径");

        // API参数名称
        promptTemplates.put("api_parameters", "你是一名资深的安全测试专家，正在进行授权的安全评估。请提供100个常见的API参数名称，用于API安全测试。\n" +
                "要求：\n" +
                "1. 每行一个参数名\n" +
                "2. 不要包含任何解释性文字\n" +
                "3. 包括认证、授权相关的参数\n" +
                "4. 包括数据操作相关的参数\n" +
                "5. 包括常见的过滤和排序参数\n" +
                "6. 按照使用频率排序");

        //
        promptTemplates.put("java_linux_history", "你是一名资深的安全测试专家，正在进行授权的安全评估。请根据以下某linux下的java 系统存在文件读取漏洞的数据包，结合bash_history的内容分析，提供100个常见的后渗透读取信息，用于深入安全测试\n" +
                "要求：\n" +
                "1. 只输出完整的文件路径如数据包中的/root/.bash_history，每行一个\n" +
                "2. 包括系统配置文件、源代码等\n" +
                "3. 不要包含任何解释性文字\n" +
                "4. 确保这些路径在大多数linux下javaweb中存在\n"+
                "5. 按照敏感程度排序\n"+
                "数据包如下：\n");
    
    }
    
    /**
     * 从文件加载配置
     * @return 是否成功加载
     */
    private boolean loadConfigFromFile() {
        try {
            File configDir = new File(CONFIG_DIR_PATH);
            File configFile = new File(CONFIG_FILE_PATH);
            
            // 如果配置文件不存在，则创建默认配置文件
            if (!configFile.exists()) {
                if (!configDir.exists()) {
                    configDir.mkdirs();
                }
                saveConfigToFile();
                return true;
            }
            
            // 使用SnakeYAML读取配置文件
            Yaml yaml = new Yaml();
            Map<String, Object> config = yaml.load(new FileInputStream(configFile));
            
            // 读取API配置
            if (config.containsKey("api")) {
                Map<String, String> apiConfig = (Map<String, String>) config.get("api");
                if (apiConfig.containsKey("api_key")) {
                    properties.setProperty(API_KEY, apiConfig.get("api_key"));
                }
                if (apiConfig.containsKey("base_url")) {
                    properties.setProperty(BASE_URL, apiConfig.get("base_url"));
                } else {
                    properties.setProperty(BASE_URL, DEFAULT_BASE_URL);
                }
                if (apiConfig.containsKey("model")) {
                    properties.setProperty(MODEL, apiConfig.get("model"));
                } else {
                    properties.setProperty(MODEL, DEFAULT_MODEL);
                }
            } else {
                properties.setProperty(BASE_URL, DEFAULT_BASE_URL);
                properties.setProperty(MODEL, DEFAULT_MODEL);
            }
            
            // 读取提示词名称
            if (config.containsKey("prompt_names")) {
                Map<String, String> names = (Map<String, String>) config.get("prompt_names");
                promptNames.put��n    // 使用SnakeYAML读�� ��uu��ODEL����roperties.setProperty(MODEL, D    �<Strino��������照敏感程��mEL, D    �<Strino��������照敏感程�o�
                if (!config�存在�// 使用Snakep�ntring> names = (n䌘�y"));
       an loa���o�
        LT_BASE_URL);
      �FAUL�tProperty(MODEL, D    �  } else {
                    properties.setStrino�����l"));
              �h��Sna     �h��Sna     �h��Sna     �h��Sna     �h��Sna     �h��Sna     �h��Sna     �h��Sna     �h��Sna     �h��Sna     �h��Sna     �h��Sna     �h��Sna     �h��Sna     �h��Sna     �h��Sna     �h��Sna     �h��Sna     �h��Sna     �h��Sna     �h��Sna     �h��Sna     �