package burp.payload;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Random;

public interface PayloadTransformer {
    
    String transform(String payload);
    
    String getName();
    
    String getDescription();
    
    public enum TransformType {
        NONE,
        URL_ENCODE,
        URL_ENCODE_ALL,
        BASE64_ENCODE,
        HTML_ENCODE,
        UNICODE_ENCODE,
        HEX_ENCODE,
        DOUBLE_URL_ENCODE,
        UPPER_CASE,
        LOWER_CASE,
        RANDOM_CASE,
        ADD_PREFIX,
        ADD_SUFFIX,
        ADD_QUOTES,
        WRAP_COMMENT
    }
}

abstract class BaseTransformer implements PayloadTransformer {
    protected String name;
    protected String description;
    
    public BaseTransformer(String name, String description) {
        this.name = name;
        this.description = description;
    }
    
    @Override
    public String getName() {
        return name;
    }
    
    @Override
    public String getDescription() {
        return description;
    }
}

class NoTransformTransformer extends BaseTransformer {
    public NoTransformTransformer() {
        super("无变换", "原始Payload不做任何变换");
    }
    
    @Override
    public String transform(String payload) {
        return payload;
    }
}

class UrlEncodeTransformer extends BaseTransformer {
    public UrlEncodeTransformer() {
        super("URL编码", "对特殊字符进行URL编码");
    }
    
    @Override
    public String transform(String payload) {
        try {
            return URLEncoder.encode(payload, "UTF-8").replace("+", "%20");
        } catch (UnsupportedEncodingException e) {
            return payload;
        }
    }
}

class UrlEncodeAllTransformer extends BaseTransformer {
    public UrlEncodeAllTransformer() {
        super("URL全编码", "对所有字符进行URL编码");
    }
    
    @Override
    public String transform(String payload) {
        StringBuilder result = new StringBuilder();
        for (char c : payload.toCharArray()) {
            try {
                result.append("%").append(String.format("%02X", (int) c));
            } catch (Exception e) {
                result.append(c);
            }
        }
        return result.toString();
    }
}

class DoubleUrlEncodeTransformer extends BaseTransformer {
    public DoubleUrlEncodeTransformer() {
        super("双重URL编码", "对Payload进行两次URL编码");
    }
    
    @Override
    public String transform(String payload) {
        try {
            String first = URLEncoder.encode(payload, "UTF-8").replace("+", "%20");
            return URLEncoder.encode(first, "UTF-8").replace("+", "%20");
        } catch (UnsupportedEncodingException e) {
            return payload;
        }
    }
}

class Base64EncodeTransformer extends BaseTransformer {
    public Base64EncodeTransformer() {
        super("Base64编码", "对Payload进行Base64编码");
    }
    
    @Override
    public String transform(String payload) {
        return Base64.getEncoder().encodeToString(payload.getBytes(StandardCharsets.UTF_8));
    }
}

class HtmlEncodeTransformer extends BaseTransformer {
    public HtmlEncodeTransformer() {
        super("HTML实体编码", "将字符转换为HTML实体");
    }
    
    @Override
    public String transform(String payload) {
        StringBuilder result = new StringBuilder();
        for (char c : payload.toCharArray()) {
            if (c > 127 || c == '<' || c == '>' || c == '&' || c == '"' || c == '\'') {
                result.append("&#").append((int) c).append(";");
            } else {
                result.append(c);
            }
        }
        return result.toString();
    }
}

class UnicodeEncodeTransformer extends BaseTransformer {
    public UnicodeEncodeTransformer() {
        super("Unicode编码", "将字符转换为Unicode转义序列");
    }
    
    @Override
    public String transform(String payload) {
        StringBuilder result = new StringBuilder();
        for (char c : payload.toCharArray()) {
            if (c > 127) {
                result.append("\\u").append(String.format("%04x", (int) c));
            } else {
                result.append(c);
            }
        }
        return result.toString();
    }
}

class HexEncodeTransformer extends BaseTransformer {
    public HexEncodeTransformer() {
        super("Hex编码", "将字符转换为十六进制");
    }
    
    @Override
    public String transform(String payload) {
        StringBuilder result = new StringBuilder();
        for (char c : payload.toCharArray()) {
            result.append(String.format("%02x", (int) c));
        }
        return result.toString();
    }
}

class UpperCaseTransformer extends BaseTransformer {
    public UpperCaseTransformer() {
        super("大写", "将Payload转换为大写");
    }
    
    @Override
    public String transform(String payload) {
        return payload.toUpperCase();
    }
}

class LowerCaseTransformer extends BaseTransformer {
    public LowerCaseTransformer() {
        super("小写", "将Payload转换为小写");
    }
    
    @Override
    public String transform(String payload) {
        return payload.toLowerCase();
    }
}

class RandomCaseTransformer extends BaseTransformer {
    private final Random random = new Random();
    
    public RandomCaseTransformer() {
        super("随机大小写", "随机转换Payload中字符的大小写");
    }
    
    @Override
    public String transform(String payload) {
        StringBuilder result = new StringBuilder();
        for (char c : payload.toCharArray()) {
            if (Character.isLetter(c)) {
                result.append(random.nextBoolean() ? Character.toUpperCase(c) : Character.toLowerCase(c));
            } else {
                result.append(c);
            }
        }
        return result.toString();
    }
}

class AddPrefixTransformer extends BaseTransformer {
    private final String prefix;
    
    public AddPrefixTransformer(String prefix) {
        super("添加前缀", "在Payload前添加指定字符串: " + prefix);
        this.prefix = prefix;
    }
    
    @Override
    public String transform(String payload) {
        return prefix + payload;
    }
}

class AddSuffixTransformer extends BaseTransformer {
    private final String suffix;
    
    public AddSuffixTransformer(String suffix) {
        super("添加后缀", "在Payload后添加指定字符串: " + suffix);
        this.suffix = suffix;
    }
    
    @Override
    public String transform(String payload) {
        return payload + suffix;
    }
}

class AddQuotesTransformer extends BaseTransformer {
    public AddQuotesTransformer() {
        super("添加引号", "在Payload外添加引号");
    }
    
    @Override
    public String transform(String payload) {
        return "\"" + payload + "\"";
    }
}

class WrapCommentTransformer extends BaseTransformer {
    public WrapCommentTransformer() {
        super("注释包装", "用SQL注释包装Payload");
    }
    
    @Override
    public String transform(String payload) {
        return "/**/" + payload + "/**/";
    }
}
