package burp.ai;

import java.util.List;
import java.util.function.Consumer;

public interface AIProvider {
    
    List<String> generate(String systemPrompt, String userPrompt) throws Exception;
    
    void generateStream(String systemPrompt, String userPrompt, 
                        Consumer<String> onChunk, 
                        Runnable onComplete,
                        Consumer<Exception> onError);
    
    boolean isConfigured();
    
    String getName();
}
