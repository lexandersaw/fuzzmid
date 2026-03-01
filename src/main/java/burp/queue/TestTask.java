package burp.queue;

import java.util.UUID;
import java.util.concurrent.Callable;

public class TestTask implements Comparable<TestTask> {
    
    private final String id;
    private final String name;
    private final int priority;
    private final Callable<TaskResult> taskCallable;
    private volatile boolean cancelled;
    
    private TaskStatus status;
    private long submittedAt;
    private long startedAt;
    private long completedAt;
    private TaskResult result;
    private String error;
    private String targetUrl;
    private String vulnType;
    private int payloadCount;
    
    public static final int PRIORITY_LOW = 1;
    public static final int PRIORITY_NORMAL = 5;
    public static final int PRIORITY_HIGH = 10;
    public static final int PRIORITY_CRITICAL = 20;
    
    public TestTask(String name, int priority, Callable<TaskResult> taskCallable) {
        this.id = UUID.randomUUID().toString().substring(0, 8);
        this.name = name;
        this.priority = Math.max(1, Math.min(20, priority));
        this.taskCallable = taskCallable;
        this.cancelled = false;
        this.status = TaskStatus.PENDING;
    }
    
    public TaskResult execute() throws Exception {
        if (cancelled) {
            throw new Exception("Task was cancelled");
        }
        return taskCallable.call();
    }
    
    public void cancel() {
        this.cancelled = true;
    }
    
    public boolean isCancelled() {
        return cancelled;
    }
    
    @Override
    public int compareTo(TestTask other) {
        return Integer.compare(other.priority, this.priority);
    }
    
    public String getId() { return id; }
    public String getName() { return name; }
    public int getPriority() { return priority; }
    public TaskStatus getStatus() { return status; }
    public void setStatus(TaskStatus status) { this.status = status; }
    public long getSubmittedAt() { return submittedAt; }
    public void setSubmittedAt(long submittedAt) { this.submittedAt = submittedAt; }
    public long getStartedAt() { return startedAt; }
    public void setStartedAt(long startedAt) { this.startedAt = startedAt; }
    public long getCompletedAt() { return completedAt; }
    public void setCompletedAt(long completedAt) { this.completedAt = completedAt; }
    public TaskResult getResult() { return result; }
    public void setResult(TaskResult result) { this.result = result; }
    public String getError() { return error; }
    public void setError(String error) { this.error = error; }
    public String getTargetUrl() { return targetUrl; }
    public void setTargetUrl(String targetUrl) { this.targetUrl = targetUrl; }
    public String getVulnType() { return vulnType; }
    public void setVulnType(String vulnType) { this.vulnType = vulnType; }
    public int getPayloadCount() { return payloadCount; }
    public void setPayloadCount(int payloadCount) { this.payloadCount = payloadCount; }
    
    public long getDuration() {
        if (startedAt > 0 && completedAt > 0) {
            return completedAt - startedAt;
        }
        return 0;
    }
    
    public long getWaitTime() {
        if (submittedAt > 0 && startedAt > 0) {
            return startedAt - submittedAt;
        }
        return 0;
    }
    
    @Override
    public String toString() {
        return String.format("TestTask{id=%s, name=%s, priority=%d, status=%s}", 
            id, name, priority, status);
    }
}
