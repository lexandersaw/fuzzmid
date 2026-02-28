package burp.util.chain;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class ChainNode {
    
    private String id;
    private String name;
    private String description;
    private NodeStatus status;
    private String requestTemplate;
    private List<Dependency> dependencies;
    private Map<String, String> extractedVariables;
    private Map<String, String> staticVariables;
    private int order;
    private int retryCount;
    private int maxRetries;
    private String lastError;
    
    public enum NodeStatus {
        PENDING,
        RUNNING,
        COMPLETED,
        FAILED,
        SKIPPED
    }
    
    public ChainNode() {
        this.dependencies = new ArrayList<>();
        this.extractedVariables = new HashMap<>();
        this.staticVariables = new HashMap<>();
        this.status = NodeStatus.PENDING;
        this.retryCount = 0;
        this.maxRetries = 3;
        this.order = 0;
    }
    
    public ChainNode(String id, String name) {
        this();
        this.id = id;
        this.name = name;
    }
    
    public boolean canExecute(Map<String, String> contextVariables) {
        if (dependencies.isEmpty()) {
            return true;
        }
        
        for (Dependency dep : dependencies) {
            String value = contextVariables.get(dep.getVariableName());
            if (value == null || value.isEmpty()) {
                return false;
            }
        }
        
        return true;
    }
    
    public Map<String, String> getAllVariables(Map<String, String> contextVariables) {
        Map<String, String> allVars = new HashMap<>();
        allVars.putAll(staticVariables);
        allVars.putAll(contextVariables);
        return allVars;
    }
    
    public void addDependency(Dependency dependency) {
        if (dependency != null) {
            dependencies.add(dependency);
        }
    }
    
    public void addExtractedVariable(String name, String extractionRule) {
        extractedVariables.put(name, extractionRule);
    }
    
    public void addStaticVariable(String name, String value) {
        staticVariables.put(name, value);
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
    
    public NodeStatus getStatus() {
        return status;
    }
    
    public void setStatus(NodeStatus status) {
        this.status = status;
    }
    
    public String getRequestTemplate() {
        return requestTemplate;
    }
    
    public void setRequestTemplate(String requestTemplate) {
        this.requestTemplate = requestTemplate;
    }
    
    public List<Dependency> getDependencies() {
        return new ArrayList<>(dependencies);
    }
    
    public void setDependencies(List<Dependency> dependencies) {
        this.dependencies = dependencies != null ? new ArrayList<>(dependencies) : new ArrayList<>();
    }
    
    public Map<String, String> getExtractedVariables() {
        return new HashMap<>(extractedVariables);
    }
    
    public void setExtractedVariables(Map<String, String> extractedVariables) {
        this.extractedVariables = extractedVariables != null ? new HashMap<>(extractedVariables) : new HashMap<>();
    }
    
    public Map<String, String> getStaticVariables() {
        return new HashMap<>(staticVariables);
    }
    
    public void setStaticVariables(Map<String, String> staticVariables) {
        this.staticVariables = staticVariables != null ? new HashMap<>(staticVariables) : new HashMap<>();
    }
    
    public int getOrder() {
        return order;
    }
    
    public void setOrder(int order) {
        this.order = order;
    }
    
    public int getRetryCount() {
        return retryCount;
    }
    
    public void setRetryCount(int retryCount) {
        this.retryCount = retryCount;
    }
    
    public int getMaxRetries() {
        return maxRetries;
    }
    
    public void setMaxRetries(int maxRetries) {
        this.maxRetries = maxRetries;
    }
    
    public String getLastError() {
        return lastError;
    }
    
    public void setLastError(String lastError) {
        this.lastError = lastError;
    }
    
    public boolean canRetry() {
        return retryCount < maxRetries;
    }
    
    public void incrementRetry() {
        retryCount++;
    }
    
    @Override
    public String toString() {
        return "ChainNode{" +
                "id='" + id + '\'' +
                ", name='" + name + '\'' +
                ", status=" + status +
                ", order=" + order +
                '}';
    }
    
    public static class Dependency {
        private String nodeRef;
        private String variableName;
        private String extractionPattern;
        
        public Dependency() {}
        
        public Dependency(String nodeRef, String variableName) {
            this.nodeRef = nodeRef;
            this.variableName = variableName;
        }
        
        public String getNodeRef() {
            return nodeRef;
        }
        
        public void setNodeRef(String nodeRef) {
            this.nodeRef = nodeRef;
        }
        
        public String getVariableName() {
            return variableName;
        }
        
        public void setVariableName(String variableName) {
            this.variableName = variableName;
        }
        
        public String getExtractionPattern() {
            return extractionPattern;
        }
        
        public void setExtractionPattern(String extractionPattern) {
            this.extractionPattern = extractionPattern;
        }
    }
}
