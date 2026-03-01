package burp.queue;

import java.util.concurrent.*;
import java.util.*;
import java.util.function.Consumer;

import burp.util.ConcurrentTaskExecutor;

public class TaskQueueManager {
    
    private static final int DEFAULT_MAX_CONCURRENT = 4;
    private static final int DEFAULT_QUEUE_CAPACITY = 100;
    
    private final ConcurrentTaskExecutor executor;
    private final PriorityBlockingQueue<TestTask> taskQueue;
    private final Map<String, TestTask> runningTasks;
    private final Map<String, TestTask> completedTasks;
    private final List<TaskStatusListener> statusListeners;
    private final int maxConcurrentTasks;
    private volatile boolean running;
    private volatile boolean paused;
    
    public TaskQueueManager() {
        this(DEFAULT_MAX_CONCURRENT, DEFAULT_QUEUE_CAPACITY);
    }
    
    public TaskQueueManager(int maxConcurrentTasks, int queueCapacity) {
        this.maxConcurrentTasks = maxConcurrentTasks;
        this.executor = new ConcurrentTaskExecutor(maxConcurrentTasks, queueCapacity);
        this.taskQueue = new PriorityBlockingQueue<>(queueCapacity);
        this.runningTasks = new ConcurrentHashMap<>();
        this.completedTasks = new ConcurrentHashMap<>();
        this.statusListeners = new ArrayList<>();
        this.running = false;
        this.paused = false;
    }
    
    public String submitTask(TestTask task) {
        task.setStatus(TaskStatus.QUEUED);
        task.setSubmittedAt(System.currentTimeMillis());
        taskQueue.offer(task);
        notifyStatusListeners(task, TaskStatus.QUEUED);
        
        if (!running) {
            startProcessing();
        }
        
        return task.getId();
    }
    
    public String submitTask(String name, int priority, Callable<TaskResult> taskCallable) {
        TestTask task = new TestTask(name, priority, taskCallable);
        return submitTask(task);
    }
    
    public void cancelTask(String taskId) {
        TestTask task = runningTasks.get(taskId);
        if (task != null) {
            task.cancel();
            task.setStatus(TaskStatus.CANCELLED);
            notifyStatusListeners(task, TaskStatus.CANCELLED);
        } else {
            taskQueue.removeIf(t -> t.getId().equals(taskId));
        }
    }
    
    public void pauseQueue() {
        paused = true;
    }
    
    public void resumeQueue() {
        paused = false;
        processNextTask();
    }
    
    public void startProcessing() {
        if (running) return;
        running = true;
        processNextTask();
    }
    
    public void stopProcessing() {
        running = false;
        paused = false;
        taskQueue.clear();
        for (TestTask task : runningTasks.values()) {
            task.cancel();
            task.setStatus(TaskStatus.CANCELLED);
        }
        runningTasks.clear();
    }
    
    private void processNextTask() {
        if (!running || paused) return;
        if (runningTasks.size() >= maxConcurrentTasks) return;
        
        TestTask task = taskQueue.poll();
        if (task == null) return;
        
        runningTasks.put(task.getId(), task);
        task.setStatus(TaskStatus.RUNNING);
        task.setStartedAt(System.currentTimeMillis());
        notifyStatusListeners(task, TaskStatus.RUNNING);
        
        executor.submitTask(() -> {
            try {
                TaskResult result = task.execute();
                task.setResult(result);
                task.setStatus(TaskStatus.COMPLETED);
                task.setCompletedAt(System.currentTimeMillis());
                completedTasks.put(task.getId(), task);
                notifyStatusListeners(task, TaskStatus.COMPLETED);
            } catch (Exception e) {
                task.setError(e.getMessage());
                task.setStatus(TaskStatus.FAILED);
                task.setCompletedAt(System.currentTimeMillis());
                notifyStatusListeners(task, TaskStatus.FAILED);
            } finally {
                runningTasks.remove(task.getId());
                processNextTask();
            }
        });
    }
    
    private void notifyStatusListeners(TestTask task, TaskStatus status) {
        for (TaskStatusListener listener : statusListeners) {
            try {
                listener.onTaskStatusChanged(task, status);
            } catch (Exception e) {
                System.err.println("Task status listener error: " + e.getMessage());
            }
        }
    }
    
    public void addStatusListener(TaskStatusListener listener) {
        if (listener != null) {
            statusListeners.add(listener);
        }
    }
    
    public void removeStatusListener(TaskStatusListener listener) {
        statusListeners.remove(listener);
    }
    
    public TestTask getTask(String taskId) {
        TestTask task = runningTasks.get(taskId);
        if (task != null) return task;
        task = completedTasks.get(taskId);
        if (task != null) return task;
        for (TestTask t : taskQueue) {
            if (t.getId().equals(taskId)) return t;
        }
        return null;
    }
    
    public List<TestTask> getQueuedTasks() {
        return new ArrayList<>(taskQueue);
    }
    
    public List<TestTask> getRunningTasks() {
        return new ArrayList<>(runningTasks.values());
    }
    
    public List<TestTask> getCompletedTasks() {
        return new ArrayList<>(completedTasks.values());
    }
    
    public int getQueueSize() {
        return taskQueue.size();
    }
    
    public int getRunningCount() {
        return runningTasks.size();
    }
    
    public int getCompletedCount() {
        return completedTasks.size();
    }
    
    public void clearCompletedTasks() {
        completedTasks.clear();
    }
    
    public void shutdown() {
        stopProcessing();
        executor.shutdown();
    }
    
    public boolean isRunning() {
        return running;
    }
    
    public boolean isPaused() {
        return paused;
    }
    
    public QueueStatistics getStatistics() {
        int successCount = 0;
        int failedCount = 0;
        for (TestTask task : completedTasks.values()) {
            if (task.getStatus() == TaskStatus.COMPLETED) successCount++;
            else if (task.getStatus() == TaskStatus.FAILED) failedCount++;
        }
        
        return new QueueStatistics(
            taskQueue.size(),
            runningTasks.size(),
            completedTasks.size(),
            successCount,
            failedCount
        );
    }
    
    public static class QueueStatistics {
        private final int queuedCount;
        private final int runningCount;
        private final int completedCount;
        private final int successCount;
        private final int failedCount;
        
        public QueueStatistics(int queuedCount, int runningCount, 
                              int completedCount, int successCount, int failedCount) {
            this.queuedCount = queuedCount;
            this.runningCount = runningCount;
            this.completedCount = completedCount;
            this.successCount = successCount;
            this.failedCount = failedCount;
        }
        
        public int getQueuedCount() { return queuedCount; }
        public int getRunningCount() { return runningCount; }
        public int getCompletedCount() { return completedCount; }
        public int getSuccessCount() { return successCount; }
        public int getFailedCount() { return failedCount; }
        public int getTotalCount() { return queuedCount + runningCount + completedCount; }
        
        public double getSuccessRate() {
            int total = successCount + failedCount;
            return total > 0 ? (double) successCount / total : 0;
        }
    }
    
    public interface TaskStatusListener {
        void onTaskStatusChanged(TestTask task, TaskStatus status);
    }
}
