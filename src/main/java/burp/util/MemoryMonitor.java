package burp.util;

import java.lang.management.ManagementFactory;
import java.lang.management.MemoryMXBean;
import java.lang.management.MemoryUsage;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Timer;
import java.util.TimerTask;
import java.util.concurrent.ConcurrentHashMap;

public class MemoryMonitor {
    
    private static final MemoryMonitor INSTANCE = new MemoryMonitor();
    
    private final MemoryMXBean memoryBean;
    private final Map<String, MemoryTracker> trackers;
    private final List<MemoryWarningListener> warningListeners;
    private final long warningThresholdBytes;
    private final double warningThresholdPercent;
    private Timer monitorTimer;
    private volatile boolean monitoring;
    
    private MemoryMonitor() {
        this.memoryBean = ManagementFactory.getMemoryMXBean();
        this.trackers = new ConcurrentHashMap<>();
        this.warningListeners = new ArrayList<>();
        this.warningThresholdBytes = 100 * 1024 * 1024; // 100MB
        this.warningThresholdPercent = 0.85; // 85%
        this.monitoring = false;
    }
    
    public static MemoryMonitor getInstance() {
        return INSTANCE;
    }
    
    public void startMonitoring(long intervalMs) {
        if (monitoring) {
            return;
        }
        
        monitoring = true;
        monitorTimer = new Timer("MemoryMonitor", true);
        monitorTimer.scheduleAtFixedRate(new TimerTask() {
            @Override
            public void run() {
                checkMemoryUsage();
            }
        }, intervalMs, intervalMs);
    }
    
    public void stopMonitoring() {
        monitoring = false;
        if (monitorTimer != null) {
            monitorTimer.cancel();
            monitorTimer = null;
        }
    }
    
    private void checkMemoryUsage() {
        MemoryUsage heapUsage = memoryBean.getHeapMemoryUsage();
        long used = heapUsage.getUsed();
        long max = heapUsage.getMax();
        double usagePercent = (double) used / max;
        
        if (usagePercent >= warningThresholdPercent) {
            MemoryWarning warning = new MemoryWarning(
                used, max, usagePercent, System.currentTimeMillis()
            );
            
            for (MemoryWarningListener listener : warningListeners) {
                try {
                    listener.onMemoryWarning(warning);
                } catch (Exception e) {
                    // Ignore listener errors
                }
            }
        }
    }
    
    public void trackAllocation(String name, long bytes) {
        trackers.computeIfAbsent(name, k -> new MemoryTracker(name)).addAllocation(bytes);
    }
    
    public void trackDeallocation(String name, long bytes) {
        MemoryTracker tracker = trackers.get(name);
        if (tracker != null) {
            tracker.addDeallocation(bytes);
        }
    }
    
    public MemoryTracker getTracker(String name) {
        return trackers.get(name);
    }
    
    public List<MemoryTracker> getAllTrackers() {
        return new ArrayList<>(trackers.values());
    }
    
    public void addWarningListener(MemoryWarningListener listener) {
        if (listener != null) {
            warningListeners.add(listener);
        }
    }
    
    public void removeWarningListener(MemoryWarningListener listener) {
        warningListeners.remove(listener);
    }
    
    public MemorySnapshot getSnapshot() {
        MemoryUsage heapUsage = memoryBean.getHeapMemoryUsage();
        MemoryUsage nonHeapUsage = memoryBean.getNonHeapMemoryUsage();
        
        return new MemorySnapshot(
            heapUsage.getUsed(),
            heapUsage.getMax(),
            heapUsage.getCommitted(),
            nonHeapUsage.getUsed(),
            nonHeapUsage.getMax(),
            Runtime.getRuntime().freeMemory(),
            Runtime.getRuntime().totalMemory(),
            System.currentTimeMillis()
        );
    }
    
    public void triggerGC() {
        System.gc();
    }
    
    public boolean isMonitoring() {
        return monitoring;
    }
    
    public static class MemoryTracker {
        private final String name;
        private final List<AllocationRecord> allocations;
        private long totalAllocated;
        private long totalDeallocated;
        private long currentUsage;
        private long peakUsage;
        
        public MemoryTracker(String name) {
            this.name = name;
            this.allocations = new ArrayList<>();
            this.totalAllocated = 0;
            this.totalDeallocated = 0;
            this.currentUsage = 0;
            this.peakUsage = 0;
        }
        
        public synchronized void addAllocation(long bytes) {
            totalAllocated += bytes;
            currentUsage += bytes;
            peakUsage = Math.max(peakUsage, currentUsage);
            allocations.add(new AllocationRecord(bytes, true, System.currentTimeMillis()));
        }
        
        public synchronized void addDeallocation(long bytes) {
            totalDeallocated += bytes;
            currentUsage = Math.max(0, currentUsage - bytes);
            allocations.add(new AllocationRecord(bytes, false, System.currentTimeMillis()));
        }
        
        public String getName() { return name; }
        public long getTotalAllocated() { return totalAllocated; }
        public long getTotalDeallocated() { return totalDeallocated; }
        public long getCurrentUsage() { return currentUsage; }
        public long getPeakUsage() { return peakUsage; }
        
        public List<AllocationRecord> getRecentAllocations(int count) {
            int start = Math.max(0, allocations.size() - count);
            return new ArrayList<>(allocations.subList(start, allocations.size()));
        }
    }
    
    public static class AllocationRecord {
        private final long bytes;
        private final boolean allocation;
        private final long timestamp;
        
        public AllocationRecord(long bytes, boolean allocation, long timestamp) {
            this.bytes = bytes;
            this.allocation = allocation;
            this.timestamp = timestamp;
        }
        
        public long getBytes() { return bytes; }
        public boolean isAllocation() { return allocation; }
        public long getTimestamp() { return timestamp; }
    }
    
    public static class MemoryWarning {
        private final long usedBytes;
        private final long maxBytes;
        private final double usagePercent;
        private final long timestamp;
        
        public MemoryWarning(long usedBytes, long maxBytes, double usagePercent, long timestamp) {
            this.usedBytes = usedBytes;
            this.maxBytes = maxBytes;
            this.usagePercent = usagePercent;
            this.timestamp = timestamp;
        }
        
        public long getUsedBytes() { return usedBytes; }
        public long getMaxBytes() { return maxBytes; }
        public double getUsagePercent() { return usagePercent; }
        public long getTimestamp() { return timestamp; }
        
        public String getFormattedUsed() {
            return formatBytes(usedBytes);
        }
        
        public String getFormattedMax() {
            return formatBytes(maxBytes);
        }
        
        private String formatBytes(long bytes) {
            if (bytes < 1024) return bytes + " B";
            if (bytes < 1024 * 1024) return String.format("%.1f KB", bytes / 1024.0);
            if (bytes < 1024 * 1024 * 1024) return String.format("%.1f MB", bytes / (1024.0 * 1024));
            return String.format("%.1f GB", bytes / (1024.0 * 1024 * 1024));
        }
    }
    
    public interface MemoryWarningListener {
        void onMemoryWarning(MemoryWarning warning);
    }
    
    public static class MemorySnapshot {
        private final long heapUsed;
        private final long heapMax;
        private final long heapCommitted;
        private final long nonHeapUsed;
        private final long nonHeapMax;
        private final long freeMemory;
        private final long totalMemory;
        private final long timestamp;
        
        public MemorySnapshot(long heapUsed, long heapMax, long heapCommitted,
                            long nonHeapUsed, long nonHeapMax,
                            long freeMemory, long totalMemory, long timestamp) {
            this.heapUsed = heapUsed;
            this.heapMax = heapMax;
            this.heapCommitted = heapCommitted;
            this.nonHeapUsed = nonHeapUsed;
            this.nonHeapMax = nonHeapMax;
            this.freeMemory = freeMemory;
            this.totalMemory = totalMemory;
            this.timestamp = timestamp;
        }
        
        public long getHeapUsed() { return heapUsed; }
        public long getHeapMax() { return heapMax; }
        public long getHeapCommitted() { return heapCommitted; }
        public long getNonHeapUsed() { return nonHeapUsed; }
        public long getNonHeapMax() { return nonHeapMax; }
        public long getFreeMemory() { return freeMemory; }
        public long getTotalMemory() { return totalMemory; }
        public long getTimestamp() { return timestamp; }
        
        public double getHeapUsagePercent() {
            return heapMax > 0 ? (double) heapUsed / heapMax : 0;
        }
        
        @Override
        public String toString() {
            return String.format("MemorySnapshot{heap=%.1f%%, used=%dMB, max=%dMB}",
                getHeapUsagePercent() * 100,
                heapUsed / (1024 * 1024),
                heapMax / (1024 * 1024));
        }
    }
}
