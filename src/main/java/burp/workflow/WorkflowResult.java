package burp.workflow;

public class WorkflowResult {
    
    private boolean success;
    private String message;
    private WorkflowContext context;
    private long executionTimeMs;
    private int completedSteps;
    private int totalSteps;
    
    public WorkflowResult() {
        this.success = false;
        this.completedSteps = 0;
        this.totalSteps = 0;
    }
    
    public WorkflowResult(boolean success, String message) {
        this();
        this.success = success;
        this.message = message;
    }
    
    public boolean isSuccess() {
        return success;
    }
    
    public void setSuccess(boolean success) {
        this.success = success;
    }
    
    public String getMessage() {
        return message;
    }
    
    public void setMessage(String message) {
        this.message = message;
    }
    
    public WorkflowContext getContext() {
        return context;
    }
    
    public void setContext(WorkflowContext context) {
        this.context = context;
    }
    
    public long getExecutionTimeMs() {
        return executionTimeMs;
    }
    
    public void setExecutionTimeMs(long executionTimeMs) {
        this.executionTimeMs = executionTimeMs;
    }
    
    public int getCompletedSteps() {
        return completedSteps;
    }
    
    public void setCompletedSteps(int completedSteps) {
        this.completedSteps = completedSteps;
    }
    
    public int getTotalSteps() {
        return totalSteps;
    }
    
    public void setTotalSteps(int totalSteps) {
        this.totalSteps = totalSteps;
    }
    
    public double getProgressPercentage() {
        if (totalSteps == 0) return 0;
        return (completedSteps * 100.0) / totalSteps;
    }
    
    public String getSummary() {
        StringBuilder sb = new StringBuilder();
        sb.append("工作流执行").append(success ? "成功" : "失败").append("\n");
        sb.append("完成步骤: ").append(completedSteps).append("/").append(totalSteps).append("\n");
        sb.append("执行时间: ").append(executionTimeMs).append("ms\n");
        if (message != null) {
            sb.append("消息: ").append(message);
        }
        return sb.toString();
    }
}
