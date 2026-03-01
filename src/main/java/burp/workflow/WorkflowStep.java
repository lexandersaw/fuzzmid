package burp.workflow;

public class WorkflowStep {
    
    private String id;
    private String name;
    private String description;
    private StepStatus status;
    private String result;
    private String error;
    
    public enum StepStatus {
        PENDING,
        RUNNING,
        COMPLETED,
        FAILED,
        SKIPPED
    }
    
    public WorkflowStep() {
        this.status = StepStatus.PENDING;
    }
    
    public WorkflowStep(String id, String name, String description) {
        this();
        this.id = id;
        this.name = name;
        this.description = description;
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
    
    public StepStatus getStatus() {
        return status;
    }
    
    public void setStatus(StepStatus status) {
        this.status = status;
    }
    
    public String getResult() {
        return result;
    }
    
    public void setResult(String result) {
        this.result = result;
    }
    
    public String getError() {
        return error;
    }
    
    public void setError(String error) {
        this.error = error;
    }
    
    public boolean isCompleted() {
        return status == StepStatus.COMPLETED;
    }
    
    public boolean isFailed() {
        return status == StepStatus.FAILED;
    }
    
    public boolean isPending() {
        return status == StepStatus.PENDING;
    }
    
    public boolean isRunning() {
        return status == StepStatus.RUNNING;
    }
}
