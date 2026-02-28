package burp.fuzzing;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class FuzzingContext {
    
    private Map<String, Object> fields;
    private Map<String, List<String>> dictionaries;
    private String originalValue;
    private String parameterName;
    private String parameterType;
    private String requestMethod;
    private String requestPath;
    private String contentType;
    private Map<String, String> headers;
    private Map<String, String> parameters;
    
    public FuzzingContext() {
        this.fields = new HashMap<>();
        this.dictionaries = new HashMap<>();
        this.headers = new HashMap<>();
        this.parameters = new HashMap<>();
    }
    
    public void setField(String name, Object value) {
        fields.put(name, value);
    }
    
    public Object getField(String name) {
        return fields.get(name);
    }
    
    public String getFieldValue(String name) {
        Object value = fields.get(name);
        if (value == null) {
            // 尝试从特定字段获取
            switch (name.toLowerCase()) {
                case "param_name":
                case "parametername":
                    return parameterName;
                case "param_type":
                case "parametertype":
                    return parameterType;
                case "original":
                case "originalvalue":
                    return originalValue;
                case "method":
                case "requestmethod":
                    return requestMethod;
                case "path":
                case "requestpath":
                    return requestPath;
                case "contenttype":
                    return contentType;
                default:
                    if (headers.containsKey(name)) {
                        return headers.get(name);
                    }
                    if (parameters.containsKey(name)) {
                        return parameters.get(name);
                    }
                    return null;
            }
        }
        return value != null ? value.toString() : null;
    }
    
    public void addDictionary(String name, List<String> entries) {
        dictionaries.put(name, entries);
    }
    
    public List<String> getDictionary(String name) {
        return dictionaries.get(name);
    }
    
    public static FuzzingContext fromParameter(String paramName, String paramValue, String paramType) {
        FuzzingContext context = new FuzzingContext();
        context.setParameterName(paramName);
        context.setOriginalValue(paramValue);
        context.setParameterType(paramType);
        context.setField("param_name", paramName);
        context.setField("param_value", paramValue);
        context.setField("param_type", paramType);
        return context;
    }
    
    public Map<String, Object> getFields() {
        return new HashMap<>(fields);
    }
    
    public void setFields(Map<String, Object> fields) {
        this.fields = fields != null ? new HashMap<>(fields) : new HashMap<>();
    }
    
    public Map<String, List<String>> getDictionaries() {
        return new HashMap<>(dictionaries);
    }
    
    public void setDictionaries(Map<String, List<String>> dictionaries) {
        this.dictionaries = dictionaries != null ? new HashMap<>(dictionaries) : new HashMap<>();
    }
    
    public String getOriginalValue() {
        return originalValue;
    }
    
    public void setOriginalValue(String originalValue) {
        this.originalValue = originalValue;
    }
    
    public String getParameterName() {
        return parameterName;
    }
    
    public void setParameterName(String parameterName) {
        this.parameterName = parameterName;
    }
    
    public String getParameterType() {
        return parameterType;
    }
    
    public void setParameterType(String parameterType) {
        this.parameterType = parameterType;
    }
    
    public String getRequestMethod() {
        return requestMethod;
    }
    
    public void setRequestMethod(String requestMethod) {
        this.requestMethod = requestMethod;
    }
    
    public String getRequestPath() {
        return requestPath;
    }
    
    public void setRequestPath(String requestPath) {
        this.requestPath = requestPath;
    }
    
    public String getContentType() {
        return contentType;
    }
    
    public void setContentType(String contentType) {
        this.contentType = contentType;
    }
    
    public Map<String, String> getHeaders() {
        return new HashMap<>(headers);
    }
    
    public void setHeaders(Map<String, String> headers) {
        this.headers = headers != null ? new HashMap<>(headers) : new HashMap<>();
    }
    
    public void addHeader(String name, String value) {
        headers.put(name, value);
    }
    
    public Map<String, String> getParameters() {
        return new HashMap<>(parameters);
    }
    
    public void setParameters(Map<String, String> parameters) {
        this.parameters = parameters != null ? new HashMap<>(parameters) : new HashMap<>();
    }
    
    public void addParameter(String name, String value) {
        parameters.put(name, value);
    }
}
