package burp;

import java.util.List;
import java.util.ArrayList;

/**
 * FuzzMind插件的Intruder有效载荷生成器
 */
public class FuzzPayloadGenerator implements IIntruderPayloadGenerator {
    private final List<String> dictionary;
    private int currentIndex;

    /**
     * 构造函数
     * @param dictionary 字典内容
     */
    public FuzzPayloadGenerator(List<String> dictionary) {
        // 确保字典不为空
        if (dictionary == null || dictionary.isEmpty()) {
            this.dictionary = new ArrayList<>();
            // 添加一个默认值，防止Intruder模块出错
            this.dictionary.add("FuzzMind - 请先选择字典");
        } else {
            this.dictionary = dictionary;
        }
        this.currentIndex = 0;
    }

    /**
     * 是否有更多的有效载荷
     * @return 是否有更多的有效载荷
     */
    @Override
    public boolean hasMorePayloads() {
        return currentIndex < dictionary.size();
    }

    /**
     * 获取下一个有效载荷
     * @param baseValue 基础值
     * @return 有效载荷的字节数组
     */
    @Override
    public byte[] getNextPayload(byte[] baseValue) {
        byte[] payload = dictionary.get(currentIndex).getBytes();
        currentIndex++;
        return payload;
    }

    /**
     * 重置有效载荷生成器
     */
    @Override
    public void reset() {
        currentIndex = 0;
    }
} 