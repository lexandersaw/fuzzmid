package burp;

import java.util.ArrayList;
import java.util.List;

import burp.payload.PayloadTransformer;
import burp.payload.PayloadTransformerFactory;

public class FuzzPayloadGenerator implements IIntruderPayloadGenerator {
    private final List<String> dictionary;
    private final List<String> transformedDictionary;
    private int currentIndex;
    
    public FuzzPayloadGenerator(List<String> dictionary) {
        if (dictionary == null || dictionary.isEmpty()) {
            this.dictionary = new ArrayList<>();
            this.dictionary.add("FuzzMind - 请先选择字典");
            this.transformedDictionary = this.dictionary;
        } else {
            this.dictionary = dictionary;
            this.transformedDictionary = dictionary;
        }
        this.currentIndex = 0;
    }
    
    public FuzzPayloadGenerator(List<String> dictionary, PayloadTransformer transformer) {
        if (dictionary == null || dictionary.isEmpty()) {
            this.dictionary = new ArrayList<>();
            this.dictionary.add("FuzzMind - 请先选择字典");
            this.transformedDictionary = this.dictionary;
        } else {
            this.dictionary = dictionary;
            this.transformedDictionary = PayloadTransformerFactory.transformList(dictionary, transformer);
        }
        this.currentIndex = 0;
    }
    
    public FuzzPayloadGenerator(List<String> dictionary, List<PayloadTransformer> transformers) {
        if (dictionary == null || dictionary.isEmpty()) {
            this.dictionary = new ArrayList<>();
            this.dictionary.add("FuzzMind - 请先选择字典");
            this.transformedDictionary = this.dictionary;
        } else {
            this.dictionary = dictionary;
            this.transformedDictionary = PayloadTransformerFactory.transformWithMultiple(dictionary, transformers);
        }
        this.currentIndex = 0;
    }
    
    public static FuzzPayloadGenerator createWithTransform(
            List<String> dictionary, 
            PayloadTransformer.TransformType transformType) {
        PayloadTransformer transformer = PayloadTransformerFactory.createTransformer(transformType);
        return new FuzzPayloadGenerator(dictionary, transformer);
    }
    
    public static FuzzPayloadGenerator createWithTransform(
            List<String> dictionary, 
            PayloadTransformer.TransformType transformType,
            String param) {
        PayloadTransformer transformer = PayloadTransformerFactory.createTransformer(transformType, param);
        return new FuzzPayloadGenerator(dictionary, transformer);
    }
    
    public static FuzzPayloadGenerator createWithVariants(List<String> dictionary) {
        List<String> allVariants = PayloadTransformerFactory.generateAllVariants(dictionary);
        return new FuzzPayloadGenerator(allVariants);
    }
    
    @Override
    public boolean hasMorePayloads() {
        return currentIndex < transformedDictionary.size();
    }
    
    @Override
    public byte[] getNextPayload(byte[] baseValue) {
        byte[] payload = transformedDictionary.get(currentIndex).getBytes();
        currentIndex++;
        return payload;
    }
    
    @Override
    public void reset() {
        currentIndex = 0;
    }
    
    public int getPayloadCount() {
        return transformedDictionary.size();
    }
    
    public String getCurrentPayload() {
        if (currentIndex < transformedDictionary.size()) {
            return transformedDictionary.get(currentIndex);
        }
        return null;
    }
}
