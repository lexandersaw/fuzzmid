package burp.util;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;

public class StorageOptimizer {
    
    private final String basePath;
    private final ReadWriteLock lock;
    private final int compressionThreshold;
    private final boolean enableCompression;
    
    public StorageOptimizer(String basePath) {
        this(basePath, true, 1024);
    }
    
    public StorageOptimizer(String basePath, boolean enableCompression, int compressionThreshold) {
        this.basePath = basePath;
        this.enableCompression = enableCompression;
        this.compressionThreshold = compressionThreshold;
        this.lock = new ReentrantReadWriteLock();
        
        initializeStorage();
    }
    
    private void initializeStorage() {
        try {
            Files.createDirectories(Paths.get(basePath));
        } catch (IOException e) {
            System.err.println("Failed to create storage directory: " + e.getMessage());
        }
    }
    
    public void saveData(String key, String data) throws IOException {
        lock.writeLock().lock();
        try {
            Path filePath = getFilePath(key);
            byte[] bytes = data.getBytes(StandardCharsets.UTF_8);
            
            if (enableCompression && bytes.length > compressionThreshold) {
                bytes = compress(bytes);
                filePath = getCompressedFilePath(key);
            }
            
            Path tempFile = Paths.get(filePath.toString() + ".tmp");
            Files.write(tempFile, bytes, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
            
            Files.move(tempFile, filePath, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
            
        } finally {
            lock.writeLock().unlock();
        }
    }
    
    public String loadData(String key) throws IOException {
        lock.readLock().lock();
        try {
            Path compressedPath = getCompressedFilePath(key);
            Path normalPath = getFilePath(key);
            
            if (Files.exists(compressedPath)) {
                byte[] compressed = Files.readAllBytes(compressedPath);
                byte[] decompressed = decompress(compressed);
                return new String(decompressed, StandardCharsets.UTF_8);
            } else if (Files.exists(normalPath)) {
                return new String(Files.readAllBytes(normalPath), StandardCharsets.UTF_8);
            }
            
            return null;
        } finally {
            lock.readLock().unlock();
        }
    }
    
    public void deleteData(String key) throws IOException {
        lock.writeLock().lock();
        try {
            Files.deleteIfExists(getFilePath(key));
            Files.deleteIfExists(getCompressedFilePath(key));
        } finally {
            lock.writeLock().unlock();
        }
    }
    
    public boolean exists(String key) {
        lock.readLock().lock();
        try {
            return Files.exists(getFilePath(key)) || Files.exists(getCompressedFilePath(key));
        } finally {
            lock.readLock().unlock();
        }
    }
    
    public long getSize(String key) throws IOException {
        lock.readLock().lock();
        try {
            Path compressedPath = getCompressedFilePath(key);
            Path normalPath = getFilePath(key);
            
            if (Files.exists(compressedPath)) {
                return Files.size(compressedPath);
            } else if (Files.exists(normalPath)) {
                return Files.size(normalPath);
            }
            
            return -1;
        } finally {
            lock.readLock().unlock();
        }
    }
    
    public List<String> listKeys() throws IOException {
        lock.readLock().lock();
        try {
            List<String> keys = new ArrayList<>();
            try (DirectoryStream<Path> stream = Files.newDirectoryStream(Paths.get(basePath))) {
                for (Path path : stream) {
                    String name = path.getFileName().toString();
                    if (name.endsWith(".gz")) {
                        keys.add(name.substring(0, name.length() - 3));
                    } else if (!name.endsWith(".tmp")) {
                        keys.add(name);
                    }
                }
            }
            return keys;
        } finally {
            lock.readLock().unlock();
        }
    }
    
    public StorageStats getStats() throws IOException {
        lock.readLock().lock();
        try {
            long totalFiles = 0;
            long totalSize = 0;
            long compressedFiles = 0;
            long compressedSize = 0;
            
            try (DirectoryStream<Path> stream = Files.newDirectoryStream(Paths.get(basePath))) {
                for (Path path : stream) {
                    if (!path.getFileName().toString().endsWith(".tmp")) {
                        totalFiles++;
                        long size = Files.size(path);
                        totalSize += size;
                        
                        if (path.getFileName().toString().endsWith(".gz")) {
                            compressedFiles++;
                            compressedSize += size;
                        }
                    }
                }
            }
            
            return new StorageStats(totalFiles, totalSize, compressedFiles, compressedSize);
        } finally {
            lock.readLock().unlock();
        }
    }
    
    public void cleanupTempFiles() throws IOException {
        lock.writeLock().lock();
        try {
            try (DirectoryStream<Path> stream = Files.newDirectoryStream(Paths.get(basePath), "*.tmp")) {
                for (Path path : stream) {
                    Files.deleteIfExists(path);
                }
            }
        } finally {
            lock.writeLock().unlock();
        }
    }
    
    private Path getFilePath(String key) {
        String safeKey = sanitizeKey(key);
        return Paths.get(basePath, safeKey);
    }
    
    private Path getCompressedFilePath(String key) {
        String safeKey = sanitizeKey(key);
        return Paths.get(basePath, safeKey + ".gz");
    }
    
    private String sanitizeKey(String key) {
        return key.replaceAll("[^a-zA-Z0-9._-]", "_");
    }
    
    private byte[] compress(byte[] data) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (GZIPOutputStream gzip = new GZIPOutputStream(baos)) {
            gzip.write(data);
        }
        return baos.toByteArray();
    }
    
    private byte[] decompress(byte[] compressed) throws IOException {
        ByteArrayInputStream bais = new ByteArrayInputStream(compressed);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (GZIPInputStream gzip = new GZIPInputStream(bais)) {
            byte[] buffer = new byte[1024];
            int len;
            while ((len = gzip.read(buffer)) > 0) {
                baos.write(buffer, 0, len);
            }
        }
        return baos.toByteArray();
    }
    
    public static class StorageStats {
        private final long totalFiles;
        private final long totalSize;
        private final long compressedFiles;
        private final long compressedSize;
        
        public StorageStats(long totalFiles, long totalSize, long compressedFiles, long compressedSize) {
            this.totalFiles = totalFiles;
            this.totalSize = totalSize;
            this.compressedFiles = compressedFiles;
            this.compressedSize = compressedSize;
        }
        
        public long getTotalFiles() { return totalFiles; }
        public long getTotalSize() { return totalSize; }
        public long getCompressedFiles() { return compressedFiles; }
        public long getCompressedSize() { return compressedSize; }
        public long getUncompressedFiles() { return totalFiles - compressedFiles; }
        public long getUncompressedSize() { return totalSize - compressedSize; }
        
        public double getCompressionRatio() {
            return totalSize > 0 ? (double) compressedSize / totalSize : 0;
        }
        
        public String getFormattedTotalSize() {
            return formatSize(totalSize);
        }
        
        private String formatSize(long bytes) {
            if (bytes < 1024) return bytes + " B";
            if (bytes < 1024 * 1024) return String.format("%.1f KB", bytes / 1024.0);
            if (bytes < 1024 * 1024 * 1024) return String.format("%.1f MB", bytes / (1024.0 * 1024));
            return String.format("%.1f GB", bytes / (1024.0 * 1024 * 1024));
        }
        
        @Override
        public String toString() {
            return String.format("StorageStats{files=%d, size=%s, compressed=%d}",
                totalFiles, getFormattedTotalSize(), compressedFiles);
        }
    }
}
