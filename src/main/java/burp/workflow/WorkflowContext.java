package burp.workflow;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class WorkflowContext {
    
    private String targetUrl;
    private String requestMethod;
    private String requestPath;
    private String contentType;
    private Map<String, String> headers;
    private String requestBody;
    private List<String> parameters;
    private List<String> technologies;
    private String detectedWAF;
    private String suggestedVulnType;
    private List<String> generatedPayloads;
    private Map<String, Object> additionalData;
    
    public WorkflowContext() {
        this.headers = new HashMap<>();
        this.parameters = new ArrayList<>();
        this.technologies = new ArrayList<>();
        this.generatedPayloads = new ArrayList<>();
        this.additionalData = new HashMap<>();
    }
    
    public String getTargetUrl() {
        return targetUrl;
    }
    
    public void setTargetUrl(String targetUrl) {
        this.targetUrl = targetUrl;
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
    
    public String getRequestBody() {
        return requestBody;
    }
    
    public void setRequestBody(String requestBody) {
        this.requestBody = requestBody;
    }
    
    public List<String> getParameters() {
        return new ArrayList<>(parameters);
    }
    
    public void setParameters(List<String> parameters) {
        this.parameters = parameters != null ? new ArrayList<>(parameters) : new ArrayList<>();
    }
    
    public void addParameter(String parameter) {
        parameters.add(parameter);
    }
    
    public List<String> getTechnologies() {
        return new ArrayList<>(technologies);
    }
    
    public void setTechnologies(List<String> technologies) {
        this.technologies = technologies != null ? new ArrayList<>(technologies) : new ArrayList<>();
    }
    
    public void addTechnology(String technology) {
        technologies.add(technology);
    }
    
    public String getDetectedWAF() {
        return detectedWAF;
    }
    
    public void setDetectedWAF(String detectedWAF) {
        this.detectedWAF = detectedWAF;
    }
    
    public String getSuggestedVulnType() {
        return suggestedVulnType;
    }
    
    public void setSuggestedVulnType(String suggestedVulnType) {
        this.suggestedVulnType = suggestedVulnType;
    }
    
    public List<String> getGeneratedPayloads() {
        return new ArrayList<>(generatedPayloads);
    }
    
    public void setGeneratedPayloads(List<String> generatedPayloads) {
        this.generatedPayloads = generatedPayloads != null ? new ArrayList<>(generatedPayloads) : new ArrayList<>();
    }
    
    public void addGeneratedPayload(String payload) {
        generatedPayloads.add(payload);
    }
    
    public void addGeneratedPayloads(List<String> payloads) {
        if (payloads != null) {
            generatedPayloads.addAll(payloads);
        }
    }
    
    public Object getAdditionalData(String key) {
        return additionalData.get(key);
    }
    
    public void setAdditionalData(String key, Object value) {
        additionalData.put(key, value);
    }
    
    public Map<String, Object> getAllAdditionalData() {
        return new HashMap<>(additionalData);
    }
}
