package burp.payload;

public abstract class MutationRule {
    
    private final String name;
    private final Type type;
    private String description;
    private boolean enabled;
    private int priority;
    
    public enum Type {
        CHAR_REPLACE,       // 字符替换
        LOGIC_EQUIV,        // 逻辑等价
        FUNC_REPLACE,       // 函数替换
        COMMENT_INJECT,     // 注释插入
        WHITESPACE_REPLACE, // 空白替代
        DOUBLE_WRITE,       // 双写绕过
        CASE_MIXED,         // 大小写混合
        NULL_BYTE,          // NULL字节
        PAREN_WRAP,         // 括号包装
        URL_ENCODE_KEYWORDS,// URL编码关键字
        XSS_EVENT_REPLACE,  // XSS事件替换
        HTML_ENTITY_ENCODE, // HTML实体编码
        UNICODE_ENCODE,     // Unicode编码
        BASE64_ENCODE,      // Base64编码
        HEX_ENCODE,         // Hex编码
        CUSTOM              // 自定义
    }
    
    public MutationRule(String name, Type type) {
        this.name = name;
        this.type = type;
        this.description = "";
        this.enabled = true;
        this.priority = 0;
    }
    
    public MutationRule(String name, Type type, String description) {
        this(name, type);
        this.description = description;
    }
    
    public abstract String apply(String payload);
    
    public String getName() {
        return name;
    }
    
    public Type getType() {
        return type;
    }
    
    public String getDescription() {
        return description;
    }
    
    public void setDescription(String description) {
        this.description = description;
    }
    
    public boolean isEnabled() {
        return enabled;
    }
    
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }
    
    public int getPriority() {
        return priority;
    }
    
    public void setPriority(int priority) {
        this.priority = priority;
    }
    
    @Override
    public String toString() {
        return "MutationRule{" +
                "name='" + name + '\'' +
                ", type=" + type +
                ", enabled=" + enabled +
                '}';
    }
}
