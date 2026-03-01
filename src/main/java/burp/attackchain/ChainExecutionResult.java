package burp.attackchain;

public class ChainExecutionResult {
    
    private boolean success;
    private String stepName;
    private String message;
    private String error;
    private String requestSnapshot;
    private String responseSnapshot;
    private boolean patternMatched;
    private long executionTime;
    
    public ChainExecutionResult() {
        this.success = false;
        this.patternMatched = false;
        this.executionTime = 0;
    }
    
    public boolean isSuccess() {
        return success;
    }
    
    public void setSuccess(boolean success) {
        this.success = success;
    }
    
    public String getStepName() {
        return stepName;
    }
    
    public void setStepName(String stepName) {
        this.stepName = stepName;
    }
    
    public String getMessage() {
        return message;
    }
    
    public void setMessage(String message) {
        this.message = message;
    }
    
    public String getError() {
        return error;
    }
    
    public void setError(String error) {
        this.error = error;
    }
    
    public String getRequestSnapshot() {
        return requestSnapshot;
    }
    
    public void setRequestSnapshot(String requestSnapshot) {
        this.requestSnapshot = requestSnapshot;
    }
    
    public String getResponseSnapshot() {
        return responseSnapshot;
    }
    
    public void setResponseSnapshot(String responseSnapshot) {
        this.responseSnapshot = responseSnapshot;
    }
    
    public boolean isPatternMatched() {
        return patternMatched;
    }
    
    public void setPatternMatched(boolean patternMatched) {
        this.patternMatched = patternMatched;
    }
    
    public long getExecutionTime() {
        return executionTime;
    }
    
    public void setExecutionTime(long executionTime) {
        this.executionTime = executionTime;
    }
    
    public String getSummary() {
        StringBuilder sb = new StringBuilder();
        sb.append("Step: ").append(stepName).append("\n");
        sb.append("Success: ").append(success ? "Yes" : "No").append("\n");
        
        if (message != null) {
            sb.append("Message: ").append(message).append("\n");
        }
        
        if (error != null) {
            sb.append("Error: ").append(error).append("\n");
        }
        
        sb.append("Execution Time: ").append(executionTime).append("ms\n");
        
        return sb.toString();
    }
    
    @Override
    public String toString() {
        return String.format("ChainExecutionResult{step='%s', success=%b, time=%dms}", 
            stepName, success, executionTime);
    }
}
