package burp.queue;

import java.util.ArrayList;
import java.util.List;

public class TaskResult {
    
    private final String taskId;
    private final boolean success;
    private final int totalRequests;
    private final int successfulRequests;
    private final int failedRequests;
    private final List<Finding> findings;
    private final long executionTime;
    private final String errorMessage;
    
    public TaskResult(String taskId, boolean success, int totalRequests,
                     int successfulRequests, int failedRequests,
                     List<Finding> findings, long executionTime) {
        this(taskId, success, totalRequests, successfulRequests, failedRequests, 
             findings, executionTime, null);
    }
    
    public TaskResult(String taskId, boolean success, int totalRequests,
                     int successfulRequests, int failedRequests,
                     List<Finding> findings, long executionTime, String errorMessage) {
        this.taskId = taskId;
        this.success = success;
        this.totalRequests = totalRequests;
        this.successfulRequests = successfulRequests;
        this.failedRequests = failedRequests;
        this.findings = findings != null ? findings : new ArrayList<>();
        this.executionTime = executionTime;
        this.errorMessage = errorMessage;
    }
    
    public String getTaskId() { return taskId; }
    public boolean isSuccess() { return success; }
    public int getTotalRequests() { return totalRequests; }
    public int getSuccessfulRequests() { return successfulRequests; }
    public int getFailedRequests() { return failedRequests; }
    public List<Finding> getFindings() { return new ArrayList<>(findings); }
    public long getExecutionTime() { return executionTime; }
    public String getErrorMessage() { return errorMessage; }
    
    public double getSuccessRate() {
        return totalRequests > 0 ? (double) successfulRequests / totalRequests : 0;
    }
    
    public int getFindingCount() {
        return findings.size();
    }
    
    public static class Finding {
        private final String type;
        private final String severity;
        private final String url;
        private final String payload;
        private final String description;
        private final String evidence;
        
        public Finding(String type, String severity, String url, String payload,
                      String description, String evidence) {
            this.type = type;
            this.severity = severity;
            this.url = url;
            this.payload = payload;
            this.description = description;
            this.evidence = evidence;
        }
        
        public String getType() { return type; }
        public String getSeverity() { return severity; }
        public String getUrl() { return url; }
        public String getPayload() { return payload; }
        public String getDescription() { return description; }
        public String getEvidence() { return evidence; }
    }
}
