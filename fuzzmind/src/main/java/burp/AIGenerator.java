package burp;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import org.json.JSONArray;
import org.json.JSONObject;

/**
 * AI生成器，用于与DeepSeek API通信并生成字典
 */
public class AIGenerator {
    private final ConfigManager configManager;
    private final IBurpExtenderCallbacks callbacks;
    
    /**
     * 构造函数
     * @param configManager 配置管理器
     * @param callbacks Burp回调对象
     */
    public AIGenerator(ConfigManager configManager, IBurpExtenderCallbacks callbacks) {
        this.configManager = configManager;
        this.callbacks = callbacks;
    }
    
    /**
     * 生成字典
     * @param promptType 提示词类型
     * @param prompt 提示词
     * @return 生成的字典内容
     * @throws Exception 生成过程中的异常
     */
    public List<String> generateDictionary(String promptType, String prompt) throws Exception {
        String apiKey = configManager.getConfig(ConfigManager.API_KEY);
        if (apiKey == null || apiKey.trim().isEmpty()) {
            throw new Exception("API密钥未配置，请先配置API密钥");
        }
        
        // 硬编码API URL，不再从配置中读取
        String apiUrl = "https://api.deepseek.com/v1/chat/completions";
        
        // 构建请求JSON
        JSONObject requestJson = new JSONObject();
        requestJson.put("model", "deepseek-chat");
        requestJson.put("temperature", 0.3);
        requestJson.put("max_tokens", 4000);
        
        JSONArray messages = new JSONArray();
        
        // 系统消息
        JSONObject systemMessage = new JSONObject();
        systemMessage.put("role", "system");
        systemMessage.put("content", "你是一名资深的网络安全专家，专注于渗透测试和漏洞挖掘。");
        messages.put(systemMessage);
        
        // 用户消息
        JSONObject userMessage = new JSONObject();
        userMessage.put("role", "user");
        userMessage.put("content", prompt);
        messages.put(userMessage);
        
        requestJson.put("messages", messages);
        
        // 发送请求
        URL url = new URL(apiUrl);
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("POST");
        connection.setRequestProperty("Content-Type", "application/json");
        connection.setRequestProperty("Authorization", "Bearer " + apiKey);
        connection.setDoOutput(true);
        
        // 写入请求体
        try (OutputStream os = connection.getOutputStream()) {
            byte[] input = requestJson.toString().getBytes(StandardCharsets.UTF_8);
            os.write(input, 0, input.length);
        }
        
        // 获取响应
        int responseCode = connection.getResponseCode();
        if (responseCode != 200) {
            BufferedReader errorReader = new BufferedReader(new InputStreamReader(connection.getErrorStream()));
            StringBuilder errorResponse = new StringBuilder();
            String errorLine;
            while ((errorLine = errorReader.readLine()) != null) {
                errorResponse.append(errorLine);
            }
            errorReader.close();
            throw new Exception("API请求失败，状态码: " + responseCode + ", 错误信息: " + errorResponse.toString());
        }
        
        // 读取响应内容
        BufferedReader reader = new BufferedReader(new InputStreamReader(connection.getInputStream()));
        StringBuilder response = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            response.append(line);
        }
        reader.close();
        
        // 解析响应JSON
        JSONObject responseJson = new JSONObject(response.toString());
        String generatedText = responseJson.getJSONArray("choices").getJSONObject(0).getJSONObject("message").getString("content");
        
        // 处理生成的文本，去除可能的解释性文字
        List<String> payloads = new ArrayList<>();
        for (String payloadLine : generatedText.strip().split("\n")) {
            payloadLine = payloadLine.strip();
            if (!payloadLine.isEmpty() && !payloadLine.startsWith("#") && !payloadLine.startsWith("```")) {
                // 移除可能的序号前缀
                if (payloadLine.matches("^\\d+\\.\\s.*")) {
                    payloadLine = payloadLine.replaceFirst("^\\d+\\.\\s+", "");
                }
                payloads.add(payloadLine);
            }
        }
        
        return payloads;
    }
} 