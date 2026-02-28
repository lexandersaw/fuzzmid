package burp.waf;

import java.util.List;

public class BypassResult {
    
    private String originalPayload;
    private String bypassedPayload;
    private String techniqueId;
    private String techniqueName;
    private boolean successful;
    private int attemptCount;
    private long duration;
    private String errorMessage;
    private List<String> attemptedPayloads;
    
    public BypassResult() {
        this.successful = false;
        this.attemptCount = 0;
        this.duration = 0;
    }
    
    public BypassResult(String originalPayload, String bypassedPayload, String techniqueId) {
        this();
        this.originalPayload = originalPayload;
        this.bypassedPayload = bypassedPayload;
        this.techniqueId = techniqueId;
    }
    
    public String getOriginalPayload() {
        return originalPayload;
    }
    
    public void setOriginalPayload(String originalPayload) {
        this.originalPayload = originalPayload;
    }
    
    public String getBypassedPayload() {
        return bypassedPayload;
    }
    
    public void setBypassedPayload(String bypassedPayload) {
        this.bypassedPayload = bypassedPayload;
    }
    
    public String getTechniqueId() {
        return techniqueId;
    }
    
    public void setTechniqueId(String techniqueId) {
        this.techniqueId = techniqueId;
    }
    
    public String getTechniqueName() {
        return techniqueName;
    }
    
    public void setTechniqueName(String techniqueName) {
        this.techniqueName = techniqueName;
    }
    
    public boolean isSuccessful() {
        return successful;
    }
    
    public void setSuccessful(boolean successful) {
        this.successful = successful;
    }
    
    public int getAttemptCount() {
        return attemptCount;
    }
    
    public void setAttemptCount(int attemptCount) {
        this.attemptCount = attemptCount;
    }
    
    public long getDuration() {
        return duration;
    }
    
    public void setDuration(long duration) {
        this.duration = duration;
    }
    
    public String getErrorMessage() {
        return errorMessage;
    }
    
    public void setErrorMessage(String errorMessage) {
        this.errorMessage = errorMessage;
    }
    
    public List<String> getAttemptedPayloads() {
        return attemptedPayloads;
    }
    
    public void setAttemptedPayloads(List<String> attemptedPayloads) {
        this.attemptedPayloads = attemptedPayloads;
    }
    
    public void addAttemptedPayload(String payload) {
        if (attemptedPayloads != null && payload != null) {
            attemptedPayloads.add(payload);
        }
    }
    
    @Override
    public String toString() {
        return "BypassResult{" +
                "techniqueId='" + techniqueId + '\'' +
                ", successful=" + successful +
                ", attemptCount=" + attemptCount +
                '}';
    }
}
