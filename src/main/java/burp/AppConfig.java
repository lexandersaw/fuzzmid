package burp;

public class AppConfig {
    
    private AppConfig() {}
    
    public static final int DEFAULT_TIMEOUT_MS = 60000;
    public static final int MAX_RETRIES = 3;
    public static final int RETRY_DELAY_MS = 1000;
    
    public static final int THREAD_POOL_SIZE = 4;
    public static final int TASK_QUEUE_CAPACITY = 50;
    
    public static final int AI_CACHE_MAX_SIZE = 100;
    public static final int AI_CACHE_EXPIRE_HOURS = 24;
    
    public static final int MAX_PAYLOAD_VARIANTS = 10000;
    public static final int MAX_MUTATION_DEPTH = 5;
    
    public static final int MAX_HISTORY_RECORDS = 100;
    
    public static final int MAX_DICTIONARY_SIZE = 100000;
    public static final int PAGE_SIZE = 1000;
    
    public static final long MEMORY_WARNING_THRESHOLD = 100 * 1024 * 1024;
    public static final long MEMORY_CRITICAL_THRESHOLD = 50 * 1024 * 1024;
    
    public static final int HTTP_CONNECT_TIMEOUT_MS = 30000;
    public static final int HTTP_READ_TIMEOUT_MS = 60000;
    
    public static final String DEFAULT_BASE_URL = "https://api.openai.com/v1/chat/completions";
    public static final String DEFAULT_MODEL = "gpt-3.5-turbo";
    
    public static final String CONFIG_DIR_NAME = ".config/fuzzMind";
    public static final String CONFIG_FILE_NAME = "Config.yml";
    public static final String CACHE_DIR_NAME = "cache";
    public static final String HISTORY_DIR_NAME = "history";
}
