package burp.attackchain;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import burp.IHttpRequestResponse;

public class AttackChain {
    
    private String id;
    private String templateName;
    private IHttpRequestResponse baseRequest;
    private List<ChainStep> steps;
    private int currentStepIndex;
    private AttackChainStatus status;
    private long startTime;
    private long endTime;
    private List<String> executionLog;
    
    public AttackChain(String id) {
        this.id = id;
        this.steps = new ArrayList<>();
        this.currentStepIndex = 0;
        this.status = AttackChainStatus.PENDING;
        this.executionLog = new ArrayList<>();
        this.startTime = 0;
        this.endTime = 0;
    }
    
    public enum AttackChainStatus {
        PENDING, RUNNING, PAUSED, COMPLETED, FAILED, CANCELLED
    }
    
    public String getId() {
        return id;
    }
    
    public void setId(String id) {
        this.id = id;
    }
    
    public String getTemplateName() {
        return templateName;
    }
    
    public void setTemplateName(String templateName) {
        this.templateName = templateName;
    }
    
    public IHttpRequestResponse getBaseRequest() {
        return baseRequest;
    }
    
    public void setBaseRequest(IHttpRequestResponse baseRequest) {
        this.baseRequest = baseRequest;
    }
    
    public List<ChainStep> getSteps() {
        return new ArrayList<>(steps);
    }
    
    public void setSteps(List<ChainStep> steps) {
        this.steps = steps != null ? new ArrayList<>(steps) : new ArrayList<>();
    }
    
    public void addStep(ChainStep step) {
        if (step != null) {
            step.setOrder(steps.size());
            steps.add(step);
        }
    }
    
    public ChainStep getStep(int index) {
        if (index >= 0 && index < steps.size()) {
            return steps.get(index);
        }
        return null;
    }
    
    public int getStepCount() {
        return steps.size();
    }
    
    public int getCurrentStepIndex() {
        return currentStepIndex;
    }
    
    public void setCurrentStepIndex(int index) {
        this.currentStepIndex = Math.max(0, Math.min(index, steps.size() - 1));
    }
    
    public ChainStep getCurrentStep() {
        return getStep(currentStepIndex);
    }
    
    public AttackChainStatus getStatus() {
        return status;
    }
    
    public void setStatus(AttackChainStatus status) {
        this.status = status;
    }
    
    public long getStartTime() {
        return startTime;
    }
    
    public void setStartTime(long startTime) {
        this.startTime = startTime;
    }
    
    public long getEndTime() {
        return endTime;
    }
    
    public void setEndTime(long endTime) {
        this.endTime = endTime;
    }
    
    public long getDuration() {
        if (startTime == 0) return 0;
        if (endTime == 0) return System.currentTimeMillis() - startTime;
        return endTime - startTime;
    }
    
    public List<String> getExecutionLog() {
        return new ArrayList<>(executionLog);
    }
    
    public void addLogEntry(String entry) {
        String timestamp = new java.text.SimpleDateFormat("HH:mm:ss").format(new java.util.Date());
        executionLog.add("[" + timestamp + "] " + entry);
    }
    
    public int getCompletedStepCount() {
        int count = 0;
        for (ChainStep step : steps) {
            if (step.getStatus() == ChainStep.StepStatus.SUCCESS || 
                step.getStatus() == ChainStep.StepStatus.SKIPPED) {
                count++;
            }
        }
        return count;
    }
    
    public int getFailedStepCount() {
        int count = 0;
        for (ChainStep step : steps) {
            if (step.getStatus() == ChainStep.StepStatus.FAILED) {
                count++;
            }
        }
        return count;
    }
    
    public double getProgress() {
        if (steps.isEmpty()) return 0;
        return (double) getCompletedStepCount() / steps.size() * 100;
    }
    
    public void start() {
        if (status == AttackChainStatus.PENDING) {
            status = AttackChainStatus.RUNNING;
            startTime = System.currentTimeMillis();
            addLogEntry("Attack chain started");
        }
    }
    
    public void pause() {
        if (status == AttackChainStatus.RUNNING) {
            status = AttackChainStatus.PAUSED;
            addLogEntry("Attack chain paused");
        }
    }
    
    public void resume() {
        if (status == AttackChainStatus.PAUSED) {
            status = AttackChainStatus.RUNNING;
            addLogEntry("Attack chain resumed");
        }
    }
    
    public void complete() {
        status = AttackChainStatus.COMPLETED;
        endTime = System.currentTimeMillis();
        addLogEntry("Attack chain completed in " + getDuration() + "ms");
    }
    
    public void fail(String reason) {
        status = AttackChainStatus.FAILED;
        endTime = System.currentTimeMillis();
        addLogEntry("Attack chain failed: " + reason);
    }
    
    public void cancel() {
        status = AttackChainStatus.CANCELLED;
        endTime = System.currentTimeMillis();
        addLogEntry("Attack chain cancelled");
    }
    
    public void advanceToNextStep() {
        if (currentStepIndex < steps.size() - 1) {
            currentStepIndex++;
        }
    }
    
    public boolean hasNextStep() {
        return currentStepIndex < steps.size() - 1;
    }
    
    public String getStatusSummary() {
        StringBuilder sb = new StringBuilder();
        sb.append("Chain: ").append(templateName).append("\n");
        sb.append("Status: ").append(status).append("\n");
        sb.append("Progress: ").append(String.format("%.1f%%", getProgress())).append("\n");
        sb.append("Steps: ").append(getCompletedStepCount()).append("/").append(steps.size()).append("\n");
        sb.append("Duration: ").append(getDuration()).append("ms\n");
        
        if (!executionLog.isEmpty()) {
            sb.append("\nRecent Log:\n");
            int start = Math.max(0, executionLog.size() - 5);
            for (int i = start; i < executionLog.size(); i++) {
                sb.append("  ").append(executionLog.get(i)).append("\n");
            }
        }
        
        return sb.toString();
    }
    
    public String getStepOverview() {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < steps.size(); i++) {
            ChainStep step = steps.get(i);
            sb.append(String.format("%d. %s %s - %s\n", 
                i + 1, step.getStatusIcon(), step.getTypeIcon(), step.getName()));
        }
        return sb.toString();
    }
    
    @Override
    public String toString() {
        return String.format("AttackChain{id='%s', template='%s', status=%s, progress=%.1f%%}", 
            id, templateName, status, getProgress());
    }
}
