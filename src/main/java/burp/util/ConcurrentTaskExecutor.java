package burp.util;

import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;
import java.util.function.Supplier;

public class ConcurrentTaskExecutor {
    
    private final ExecutorService executorService;
    private final int maxThreads;
    private final int queueCapacity;
    private final AtomicInteger activeTasks;
    private final BlockingQueue<Runnable> taskQueue;
    private final RejectedExecutionHandler rejectionHandler;
    
    public ConcurrentTaskExecutor() {
        this(4, 100);
    }
    
    public ConcurrentTaskExecutor(int maxThreads, int queueCapacity) {
        this.maxThreads = Math.max(1, maxThreads);
        this.queueCapacity = Math.max(10, queueCapacity);
        this.activeTasks = new AtomicInteger(0);
        this.taskQueue = new LinkedBlockingQueue<>(this.queueCapacity);
        this.rejectionHandler = new ThreadPoolExecutor.CallerRunsPolicy();
        
        this.executorService = new ThreadPoolExecutor(
            this.maxThreads,
            this.maxThreads,
            60L, TimeUnit.SECONDS,
            taskQueue,
            new NamedThreadFactory("FuzzMind-Worker"),
            rejectionHandler
        );
    }
    
    public <T> Future<T> submitTask(Callable<T> task) {
        activeTasks.incrementAndGet();
        return executorService.submit(() -> {
            try {
                return task.call();
            } finally {
                activeTasks.decrementAndGet();
            }
        });
    }
    
    public <T> void submitTask(Supplier<T> task, Consumer<T> onSuccess, Consumer<Exception> onError) {
        activeTasks.incrementAndGet();
        executorService.submit(() -> {
            try {
                T result = task.get();
                if (onSuccess != null) {
                    onSuccess.accept(result);
                }
            } catch (Exception e) {
                if (onError != null) {
                    onError.accept(e);
                }
            } finally {
                activeTasks.decrementAndGet();
            }
        });
    }
    
    public void submitTask(Runnable task) {
        activeTasks.incrementAndGet();
        executorService.submit(() -> {
            try {
                task.run();
            } finally {
                activeTasks.decrementAndGet();
            }
        });
    }
    
    public void submitTask(Runnable task, Runnable onComplete) {
        activeTasks.incrementAndGet();
        executorService.submit(() -> {
            try {
                task.run();
            } finally {
                activeTasks.decrementAndGet();
                if (onComplete != null) {
                    onComplete.run();
                }
            }
        });
    }
    
    public <T> List<Future<T>> submitAll(List<Callable<T>> tasks) {
        List<Future<T>> futures = new ArrayList<>();
        for (Callable<T> task : tasks) {
            futures.add(submitTask(task));
        }
        return futures;
    }
    
    public void shutdown() {
        executorService.shutdown();
    }
    
    public List<Runnable> shutdownNow() {
        return executorService.shutdownNow();
    }
    
    public boolean awaitTermination(long timeout, TimeUnit unit) throws InterruptedException {
        return executorService.awaitTermination(timeout, unit);
    }
    
    public boolean isShutdown() {
        return executorService.isShutdown();
    }
    
    public boolean isTerminated() {
        return executorService.isTerminated();
    }
    
    public int getActiveTaskCount() {
        return activeTasks.get();
    }
    
    public int getQueueSize() {
        return taskQueue.size();
    }
    
    public int getMaxThreads() {
        return maxThreads;
    }
    
    public int getQueueCapacity() {
        return queueCapacity;
    }
    
    public ExecutorStatus getStatus() {
        return new ExecutorStatus(
            maxThreads,
            activeTasks.get(),
            taskQueue.size(),
            queueCapacity,
            executorService.isShutdown(),
            executorService.isTerminated()
        );
    }
    
    public static class NamedThreadFactory implements ThreadFactory {
        private final String namePrefix;
        private final AtomicInteger threadNumber;
        
        public NamedThreadFactory(String namePrefix) {
            this.namePrefix = namePrefix;
            this.threadNumber = new AtomicInteger(1);
        }
        
        @Override
        public Thread newThread(Runnable r) {
            Thread t = new Thread(r, namePrefix + "-" + threadNumber.getAndIncrement());
            t.setDaemon(true);
            return t;
        }
    }
    
    public static class ExecutorStatus {
        private final int maxThreads;
        private final int activeTasks;
        private final int queueSize;
        private final int queueCapacity;
        private final boolean shutdown;
        private final boolean terminated;
        
        public ExecutorStatus(int maxThreads, int activeTasks, int queueSize, 
                            int queueCapacity, boolean shutdown, boolean terminated) {
            this.maxThreads = maxThreads;
            this.activeTasks = activeTasks;
            this.queueSize = queueSize;
            this.queueCapacity = queueCapacity;
            this.shutdown = shutdown;
            this.terminated = terminated;
        }
        
        public int getMaxThreads() { return maxThreads; }
        public int getActiveTasks() { return activeTasks; }
        public int getQueueSize() { return queueSize; }
        public int getQueueCapacity() { return queueCapacity; }
        public boolean isShutdown() { return shutdown; }
        public boolean isTerminated() { return terminated; }
        
        public double getUtilization() {
            return maxThreads > 0 ? (double) activeTasks / maxThreads : 0;
        }
        
        public double getQueueUtilization() {
            return queueCapacity > 0 ? (double) queueSize / queueCapacity : 0;
        }
        
        @Override
        public String toString() {
            return String.format("ExecutorStatus{threads=%d/%d, queue=%d/%d, shutdown=%b}",
                activeTasks, maxThreads, queueSize, queueCapacity, shutdown);
        }
    }
}
