package burp.ai;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.json.JSONArray;
import org.json.JSONObject;

import burp.ConfigManager;

public class OpenAICompatibleProvider implements AIProvider {
    
    private final ConfigManager configManager;
    private static final int DEFAULT_TIMEOUT = 60000;
    private static final int MAX_RETRIES = 3;
    private static final int RETRY_DELAY_MS = 1000;
    private static final int THREAD_POOL_SIZE = 10;
    
    private final ExecutorService executorService = Executors.newFixedThreadPool(THREAD_POOL_SIZE);
    
    public OpenAICompatibleProvider(ConfigManager configManager) {
        this.configManager = configManager;
    }
    
    public void shutdown() {
        executorService.shutdown();
        try {
            if (!executorService.awaitTermination(5, TimeUnit.SECONDS)) {
                executorService.shutdownNow();
            }
        } catch (InterruptedException e) {
            executorService.shutdownNow();
        }
    }
    
    @Override
    public String getName() {
        return "OpenAI Compatible";
    }
    
    @Override
    public boolean isConfigured() {
        String apiKey = configManager.getConfig(ConfigManager.API_KEY);
        return apiKey != null && !apiKey.trim().isEmpty();
    }
    
    @Override
    public List<String> generate(String systemPrompt, String userPrompt) throws Exception {
        if (!isConfigured()) {
            throw new Exception("API密钥未配置，请先配置API密钥");
        }
        
        String baseUrl = configManager.getConfig(ConfigManager.BASE_URL, 
                "https://api.openai.com/v1/chat/completions");
        String model = configManager.getConfig(ConfigManager.MODEL, "gpt-3.5-turbo");
        int timeout = getTimeout();
        
        JSONObject requestJson = buildRequestJson(systemPrompt, userPrompt, model, false);
        
        HttpURLConnection connection = createConnection(baseUrl, timeout);
        
        try {
            writeRequest(connection, requestJson.toString());
            
            int responseCode = connection.getResponseCode();
            
            if (responseCode == 429 || responseCode >= 500) {
                return retryWithBackoff(systemPrompt, userPrompt, baseUrl, model, timeout, 0);
            }
            
            if (responseCode != 200) {
                String errorResponse = readErrorResponse(connection);
                throw new Exception("API请求失败，状态码: " + responseCode + ", 错误信息: " + errorResponse);
            }
            
            String response = readResponse(connection);
            return parseResponse(response);
            
        } finally {
            connection.disconnect();
        }
    }
    
    @Override
    public void generateStream(String systemPrompt, String userPrompt,
                               Consumer<String> onChunk,
                               Runnable onComplete,
                               Consumer<Exception> onError) {
        executorService.submit(() -> {
            try {
                if (!isConfigured()) {
                    onError.accept(new Exception("API密钥未配置，请先配置API密钥"));
                    return;
                }
                
                String baseUrl = configManager.getConfig(ConfigManager.BASE_URL, 
                        "https://api.openai.com/v1/chat/completions");
                String model = configManager.getConfig(ConfigManager.MODEL, "gpt-3.5-turbo");
                int timeout = getTimeout();
                
                JSONObject requestJson = buildRequestJson(systemPrompt, userPrompt, model, true);
                
                HttpURLConnection connection = createConnection(baseUrl, timeout);
                
                try {
                    writeRequest(connection, requestJson.toString());
                    
                    int responseCode = connection.getResponseCode();
                    if (responseCode != 200) {
                        String errorResponse = readErrorResponse(connection);
                        onError.accept(new Exception("API请求失败，状态码: " + responseCode + ", 错误信息: " + errorResponse));
                        return;
                    }
                    
                    StringBuilder fullContent = new StringBuilder();
                    
                    try (BufferedReader reader = new BufferedReader(
                            new InputStreamReader(connection.getInputStream(), StandardCharsets.UTF_8))) {
                        String line;
                        while ((line = reader.readLine()) != null) {
                            if (line.startsWith("data: ")) {
                                String data = line.substring(6);
                                if ("[DONE]".equals(data)) {
                                    break;
                                }
                                
                                try {
                                    JSONObject chunkJson = new JSONObject(data);
                                    JSONArray choices = chunkJson.getJSONArray("choices");
                                    if (choices.length() > 0) {
                                        JSONObject delta = choices.getJSONObject(0).optJSONObject("delta");
                                        if (delta != null && delta.has("content")) {
                                            String content = delta.getString("content");
                                            fullContent.append(content);
                                            onChunk.accept(content);
                                        }
                                    }
                                } catch (Exception e) {
                                }
                            }
                        }
                    }
                    
                    onComplete.run();
                    
                } finally {
                    connection.disconnect();
                }
                
            } catch (Exception e) {
                onError.accept(e);
            }
        });
    }
    
    private JSONObject buildRequestJson(String systemPrompt, String userPrompt, String model, boolean stream) {
        JSONObject requestJson = new JSONObject();
        requestJson.put("model", model);
        requestJson.put("temperature", 0.3);
        requestJson.put("max_tokens", 4000);
        requestJson.put("stream", stream);
        
        JSONArray messages = new JSONArray();
        
        JSONObject systemMessage = new JSONObject();
        systemMessage.put("role", "system");
        systemMessage.put("content", systemPrompt);
        messages.put(systemMessage);
        
        JSONObject userMessage = new JSONObject();
        userMessage.put("role", "user");
        userMessage.put("content", userPrompt);
        messages.put(userMessage);
        
        requestJson.put("messages", messages);
        
        return requestJson;
    }
    
    private HttpURLConnection createConnection(String baseUrl, int timeout) throws Exception {
        URL url = new URL(baseUrl);
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("POST");
        connection.setRequestProperty("Content-Type", "application/json");
        connection.setRequestProperty("Authorization", "Bearer " + configManager.getConfig(ConfigManager.API_KEY));
        connection.setRequestProperty("Accept", "application/json");
        connection.setDoOutput(true);
        connection.setConnectTimeout(timeout);
        connection.setReadTimeout(timeout);
        return connection;
    }
    
    private void writeRequest(HttpURLConnection connection, String requestBody) throws Exception {
        try (OutputStream os = connection.getOutputStream()) {
            byte[] input = requestBody.getBytes(StandardCharsets.UTF_8);
            os.write(input, 0, input.length);
        }
    }
    
    private String readResponse(HttpURLConnection connection) throws Exception {
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(connection.getInputStream(), StandardCharsets.UTF_8))) {
            StringBuilder response = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                response.append(line);
            }
            return response.toString();
        }
    }
    
    private String readErrorResponse(HttpURLConnection connection) throws Exception {
        java.io.InputStream errorStream = connection.getErrorStream();
        if (errorStream == null) {
            return "";
        }
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(errorStream, StandardCharsets.UTF_8))) {
            StringBuilder response = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                response.append(line);
            }
            return response.toString();
        }
    }
    
    private List<String> parseResponse(String response) {
        JSONObject responseJson = new JSONObject(response);
        String generatedText = responseJson.getJSONArray("choices")
                .getJSONObject(0)
                .getJSONObject("message")
                .getString("content");
        
        return processGeneratedText(generatedText);
    }
    
    private List<String> processGeneratedText(String text) {
        List<String> payloads = new ArrayList<>();
        for (String line : text.strip().split("\n")) {
            line = line.strip();
            if (!line.isEmpty() && !line.startsWith("#") && !line.startsWith("```")) {
                if (line.matches("^\\d+\\.\\s.*")) {
                    line = line.replaceFirst("^\\d+\\.\\s+", "");
                }
                payloads.add(line);
            }
        }
        return payloads;
    }
    
    private List<String> retryWithBackoff(String systemPrompt, String userPrompt, 
                                          String baseUrl, String model, int timeout, 
                                          int retryCount) throws Exception {
        if (retryCount >= MAX_RETRIES) {
            throw new Exception("API请求失败，已达到最大重试次数");
        }
        
        try {
            Thread.sleep(RETRY_DELAY_MS * (1 << retryCount));
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new Exception("请求被中断");
        }
        
        JSONObject requestJson = buildRequestJson(systemPrompt, userPrompt, model, false);
        HttpURLConnection connection = createConnection(baseUrl, timeout);
        
        try {
            writeRequest(connection, requestJson.toString());
            
            int responseCode = connection.getResponseCode();
            
            if (responseCode == 429 || responseCode >= 500) {
                return retryWithBackoff(systemPrompt, userPrompt, baseUrl, model, timeout, retryCount + 1);
            }
            
            if (responseCode != 200) {
                String errorResponse = readErrorResponse(connection);
                throw new Exception("API请求失败，状态码: " + responseCode + ", 错误信息: " + errorResponse);
            }
            
            String response = readResponse(connection);
            return parseResponse(response);
            
        } finally {
            connection.disconnect();
        }
    }
    
    private int getTimeout() {
        try {
            String timeoutStr = configManager.getConfig("timeout");
            if (timeoutStr != null && !timeoutStr.isEmpty()) {
                return Integer.parseInt(timeoutStr) * 1000;
            }
        } catch (NumberFormatException e) {
        }
        return DEFAULT_TIMEOUT;
    }
}
