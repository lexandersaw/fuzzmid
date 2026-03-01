package burp.attackchain;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.json.JSONArray;
import org.json.JSONObject;

public class ChainStep {
    
    public enum StepType {
        INFO_GATHERING, EXPLOIT, POST_EXPLOIT
    }
    
    public enum HttpMethod {
        GET, POST, PUT, DELETE, PATCH, SSH
    }
    
    public enum StepStatus {
        PENDING, RUNNING, SUCCESS, FAILED, SKIPPED
    }
    
    private String id;
    private String name;
    private String description;
    private StepType type;
    private HttpMethod method;
    private String path;
    private String requestBody;
    private List<String> headers;
    private String successPattern;
    private String expectedOutput;
    private Map<String, String> variables;
    private StepStatus status;
    private int order;
    
    public ChainStep() {
        this.headers = new ArrayList<>();
        this.variables = new HashMap<>();
        this.status = StepStatus.PENDING;
        this.order = 0;
    }
    
    public ChainStep(String id, String name, String description, StepType type, 
                     HttpMethod method, String path, String successPattern, String expectedOutput) {
        this();
        this.id = id;
        this.name = name;
        this.description = description;
        this.type = type;
        this.method = method;
        this.path = path;
        this.successPattern = successPattern;
        this.expectedOutput = expectedOutput;
    }
    
    public ChainStep(ChainStep other) {
        this.id = other.id;
        this.name = other.name;
        this.description = other.description;
        this.type = other.type;
        this.method = other.method;
        this.path = other.path;
        this.requestBody = other.requestBody;
        this.headers = new ArrayList<>(other.headers);
        this.successPattern = other.successPattern;
        this.expectedOutput = other.expectedOutput;
        this.variables = new HashMap<>(other.variables);
        this.status = StepStatus.PENDING;
        this.order = other.order;
    }
    
    public String getId() {
        return id;
    }
    
    public void setId(String id) {
        this.id = id;
    }
    
    public String getName() {
        return name;
    }
    
    public void setName(String name) {
        this.name = name;
    }
    
    public String getDescription() {
        return description;
    }
    
    public void setDescription(String description) {
        this.description = description;
    }
    
    public StepType getType() {
        return type;
    }
    
    public void setType(StepType type) {
        this.type = type;
    }
    
    public HttpMethod getMethod() {
        return method;
    }
    
    public void setMethod(HttpMethod method) {
        this.method = method;
    }
    
    public String getPath() {
        return path;
    }
    
    public void setPath(String path) {
        this.path = path;
    }
    
    public String getRequestBody() {
        return requestBody;
    }
    
    public void setRequestBody(String requestBody) {
        this.requestBody = requestBody;
    }
    
    public ChainStep addRequestBody(String body) {
        this.requestBody = body;
        return this;
    }
    
    public List<String> getHeaders() {
        return new ArrayList<>(headers);
    }
    
    public void setHeaders(List<String> headers) {
        this.headers = headers != null ? new ArrayList<>(headers) : new ArrayList<>();
    }
    
    public ChainStep addHeader(String header) {
        if (header != null && !header.isEmpty()) {
            headers.add(header);
        }
        return this;
    }
    
    public String getSuccessPattern() {
        return successPattern;
    }
    
    public void setSuccessPattern(String successPattern) {
        this.successPattern = successPattern;
    }
    
    public String getExpectedOutput() {
        return expectedOutput;
    }
    
    public void setExpectedOutput(String expectedOutput) {
        this.expectedOutput = expectedOutput;
    }
    
    public Map<String, String> getVariables() {
        return new HashMap<>(variables);
    }
    
    public void setVariables(Map<String, String> variables) {
        this.variables = variables != null ? new HashMap<>(variables) : new HashMap<>();
    }
    
    public ChainStep addVariable(String name, String value) {
        variables.put(name, value);
        return this;
    }
    
    public StepStatus getStatus() {
        return status;
    }
    
    public void setStatus(StepStatus status) {
        this.status = status;
    }
    
    public int getOrder() {
        return order;
    }
    
    public void setOrder(int order) {
        this.order = order;
    }
    
    public String getTypeIcon() {
        switch (type) {
            case INFO_GATHERING: return "INFO";
            case EXPLOIT: return "EXPLOIT";
            case POST_EXPLOIT: return "POST";
            default: return "UNKNOWN";
        }
    }
    
    public String getStatusIcon() {
        switch (status) {
            case PENDING: return "[ ]";
            case RUNNING: return "[*]";
            case SUCCESS: return "[OK]";
            case FAILED: return "[X]";
            case SKIPPED: return "[-]";
            default: return "[?]";
        }
    }
    
    public JSONObject toJson() {
        JSONObject json = new JSONObject();
        json.put("id", id);
        json.put("name", name);
        json.put("description", description);
        json.put("type", type.name());
        json.put("method", method.name());
        json.put("path", path != null ? path : "");
        json.put("requestBody", requestBody != null ? requestBody : "");
        json.put("successPattern", successPattern != null ? successPattern : "");
        json.put("expectedOutput", expectedOutput != null ? expectedOutput : "");
        json.put("status", status.name());
        json.put("order", order);
        
        JSONArray headersArray = new JSONArray();
        for (String header : headers) {
            headersArray.put(header);
        }
        json.put("headers", headersArray);
        
        JSONObject varsObj = new JSONObject();
        for (Map.Entry<String, String> entry : variables.entrySet()) {
            varsObj.put(entry.getKey(), entry.getValue());
        }
        json.put("variables", varsObj);
        
        return json;
    }
    
    public static ChainStep fromJson(JSONObject json) {
        if (json == null) return null;
        
        ChainStep step = new ChainStep();
        step.setId(json.optString("id", ""));
        step.setName(json.optString("name", ""));
        step.setDescription(json.optString("description", ""));
        step.setType(StepType.valueOf(json.optString("type", "EXPLOIT")));
        step.setMethod(HttpMethod.valueOf(json.optString("method", "GET")));
        step.setPath(json.optString("path", ""));
        step.setRequestBody(json.optString("requestBody", ""));
        step.setSuccessPattern(json.optString("successPattern", ""));
        step.setExpectedOutput(json.optString("expectedOutput", ""));
        step.setStatus(StepStatus.valueOf(json.optString("status", "PENDING")));
        step.setOrder(json.optInt("order", 0));
        
        JSONArray headersArray = json.optJSONArray("headers");
        if (headersArray != null) {
            for (int i = 0; i < headersArray.length(); i++) {
                step.addHeader(headersArray.optString(i, ""));
            }
        }
        
        JSONObject varsObj = json.optJSONObject("variables");
        if (varsObj != null) {
            for (String key : varsObj.keySet()) {
                step.addVariable(key, varsObj.optString(key, ""));
            }
        }
        
        return step;
    }
    
    @Override
    public String toString() {
        return String.format("ChainStep{id='%s', name='%s', type=%s, status=%s}", 
            id, name, type, status);
    }
}
