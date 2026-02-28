package burp;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.NoSuchElementException;

import burp.payload.PayloadTransformer;
import burp.payload.PayloadTransformerFactory;

public class FuzzPayloadGenerator implements IIntruderPayloadGenerator {
    private static final int MAX_PAYLOAD_WARNING_THRESHOLD = 10000;
    private static final int MAX_PAYLOAD_HARD_LIMIT = 100000;
    
    private final List<String> dictionary;
    private final List<PayloadTransformer> transformers;
    private final boolean generateVariants;
    private final boolean useLazyLoading;
    private final int estimatedCount;
    
    private int currentIndex;
    private Iterator<String> lazyIterator;
    private String currentPayload;
    private boolean warnedAboutSize;
    
    public FuzzPayloadGenerator(List<String> dictionary) {
        this(dictionary, new ArrayList<>(), false);
    }
    
    public FuzzPayloadGenerator(List<String> dictionary, PayloadTransformer transformer) {
        this(dictionary, 
             transformer != null ? java.util.Collections.singletonList(transformer) : new ArrayList<>(), 
             false);
    }
    
    public FuzzPayloadGenerator(List<String> dictionary, List<PayloadTransformer> transformers) {
        this(dictionary, transformers, false);
    }
    
    private FuzzPayloadGenerator(List<String> dictionary, List<PayloadTransformer> transformers, boolean generateVariants) {
        if (dictionary == null || dictionary.isEmpty()) {
            this.dictionary = new ArrayList<>();
            this.dictionary.add("FuzzMind - 请先选择字典");
            this.transformers = new ArrayList<>();
            this.generateVariants = false;
            this.useLazyLoading = false;
            this.estimatedCount = 1;
        } else {
            this.dictionary = new ArrayList<>(dictionary);
            this.transformers = transformers != null ? new ArrayList<>(transformers) : new ArrayList<>();
            this.generateVariants = generateVariants;
            this.estimatedCount = estimatePayloadCount(this.dictionary.size(), this.transformers, generateVariants);
            this.useLazyLoading = estimatedCount > MAX_PAYLOAD_WARNING_THRESHOLD;
            
            if (estimatedCount > MAX_PAYLOAD_HARD_LIMIT) {
                throw new IllegalArgumentException(
                    "Payload数量超过硬限制 (" + MAX_PAYLOAD_HARD_LIMIT + ")，" +
                    "当前估计数量: " + estimatedCount + "。请减少字典大小或变换选项。");
            }
        }
        
        this.currentIndex = 0;
        this.currentPayload = null;
        this.warnedAboutSize = false;
        
        if (!useLazyLoading) {
            this.lazyIterator = null;
        } else {
            this.lazyIterator = null;
        }
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
        if (dictionary == null || dictionary.isEmpty()) {
            return new FuzzPayloadGenerator(dictionary);
        }
        
        int estimatedCount = estimatePayloadCount(dictionary.size(), new ArrayList<>(), true);
        
        if (estimatedCount > MAX_PAYLOAD_HARD_LIMIT) {
            throw new IllegalArgumentException(
                "生成所有变体将产生 " + estimatedCount + " 个payload，超过限制 " + MAX_PAYLOAD_HARD_LIMIT + "。\n" +
                "建议：\n" +
                "1. 减少字典大小\n" +
                "2. 使用单一变换而非生成所有变体\n" +
                "3. 分批处理字典");
        }
        
        FuzzPayloadGenerator generator = new FuzzPayloadGenerator(dictionary, new ArrayList<>(), true);
        return generator;
    }
    
    private static int estimatePayloadCount(int dictSize, List<PayloadTransformer> transformers, boolean generateVariants) {
        if (generateVariants) {
            int encoderCount = PayloadTransformerFactory.getEncodingTransformers().size();
            int caseCount = PayloadTransformerFactory.getCaseTransformers().size();
            return dictSize * encoderCount * caseCount;
        }
        return dictSize;
    }
    
    private String transformPayload(String payload) {
        if (generateVariants) {
            return payload;
        }
        
        String transformed = payload;
        for (PayloadTransformer transformer : transformers) {
            transformed = transformer.transform(transformed);
        }
        return transformed;
    }
    
    private Iterator<String> createLazyIterator() {
        if (generateVariants) {
            return new VariantIterator(dictionary);
        } else if (!transformers.isEmpty()) {
            return new TransformIterator(dictionary, transformers);
        } else {
            return dictionary.iterator();
        }
    }
    
    @Override
    public boolean hasMorePayloads() {
        if (useLazyLoading) {
            if (lazyIterator == null) {
                lazyIterator = createLazyIterator();
            }
            
            if (lazyIterator.hasNext()) {
                currentPayload = lazyIterator.next();
                return true;
            }
            return false;
        }
        
        if (!warnedAboutSize && estimatedCount > MAX_PAYLOAD_WARNING_THRESHOLD && currentIndex == 0) {
            System.err.println("警告: Payload数量较多 (" + estimatedCount + ")，建议分批处理或使用更小的字典");
            warnedAboutSize = true;
        }
        
        return currentIndex < estimatedCount;
    }
    
    @Override
    public byte[] getNextPayload(byte[] baseValue) {
        if (useLazyLoading) {
            if (currentPayload == null) {
                if (!hasMorePayloads()) {
                    throw new NoSuchElementException("No more payloads available");
                }
            }
            
            String payload = currentPayload;
            currentPayload = null;
            currentIndex++;
            return payload.getBytes();
        }
        
        if (generateVariants) {
            int encoderIndex = currentIndex / (dictionary.size() * PayloadTransformerFactory.getCaseTransformers().size());
            int remaining = currentIndex % (dictionary.size() * PayloadTransformerFactory.getCaseTransformers().size());
            int caseIndex = remaining / dictionary.size();
            int dictIndex = remaining % dictionary.size();
            
            String original = dictionary.get(dictIndex);
            String encoded = PayloadTransformerFactory.getEncodingTransformers().get(encoderIndex).transform(original);
            String finalPayload = PayloadTransformerFactory.getCaseTransformers().get(caseIndex).transform(encoded);
            
            currentIndex++;
            return finalPayload.getBytes();
        }
        
        if (!transformers.isEmpty()) {
            int dictIndex = currentIndex % dictionary.size();
            String payload = transformPayload(dictionary.get(dictIndex));
            currentIndex++;
            return payload.getBytes();
        }
        
        byte[] payload = dictionary.get(currentIndex).getBytes();
        currentIndex++;
        return payload;
    }
    
    @Override
    public void reset() {
        currentIndex = 0;
        currentPayload = null;
        if (lazyIterator != null) {
            lazyIterator = createLazyIterator();
        }
    }
    
    public int getPayloadCount() {
        return estimatedCount;
    }
    
    public String getCurrentPayload() {
        if (currentIndex < estimatedCount) {
            if (useLazyLoading && currentPayload != null) {
                return currentPayload;
            }
            return dictionary.get(currentIndex % dictionary.size());
        }
        return null;
    }
    
    public static void checkPayloadLimit(List<String> dictionary, List<PayloadTransformer> transformers, boolean generateVariants) {
        if (dictionary == null || dictionary.isEmpty()) {
            return;
        }
        
        int estimatedCount = estimatePayloadCount(dictionary.size(), transformers, generateVariants);
        
        if (estimatedCount > MAX_PAYLOAD_HARD_LIMIT) {
            throw new IllegalArgumentException(
                "Payload数量将超过限制 (" + MAX_PAYLOAD_HARD_LIMIT + ")。\n" +
                "当前估计: " + estimatedCount + " 个payload\n" +
                "字典大小: " + dictionary.size() + "\n" +
                "请减少字典大小或变换选项。");
        }
        
        if (estimatedCount > MAX_PAYLOAD_WARNING_THRESHOLD) {
            System.err.println("警告: 即将生成大量payload (" + estimatedCount + ")，这可能会消耗大量内存。");
        }
    }
    
    private static class TransformIterator implements Iterator<String> {
        private final Iterator<String> dictIterator;
        private final List<PayloadTransformer> transformers;
        
        public TransformIterator(List<String> dictionary, List<PayloadTransformer> transformers) {
            this.dictIterator = dictionary.iterator();
            this.transformers = transformers;
        }
        
        @Override
        public boolean hasNext() {
            return dictIterator.hasNext();
        }
        
        @Override
        public String next() {
            String payload = dictIterator.next();
            for (PayloadTransformer transformer : transformers) {
                payload = transformer.transform(payload);
            }
            return payload;
        }
    }
    
    private static class VariantIterator implements Iterator<String> {
        private final List<String> dictionary;
        private int dictIndex = 0;
        private int encoderIndex = 0;
        private int caseIndex = 0;
        private boolean hasNext = true;
        
        public VariantIterator(List<String> dictionary) {
            this.dictionary = dictionary;
            if (dictionary.isEmpty()) {
                hasNext = false;
            }
        }
        
        @Override
        public boolean hasNext() {
            return hasNext;
        }
        
        @Override
        public String next() {
            if (!hasNext) {
                throw new NoSuchElementException();
            }
            
            String original = dictionary.get(dictIndex);
            String encoded = PayloadTransformerFactory.getEncodingTransformers().get(encoderIndex).transform(original);
            String result = PayloadTransformerFactory.getCaseTransformers().get(caseIndex).transform(encoded);
            
            caseIndex++;
            if (caseIndex >= PayloadTransformerFactory.getCaseTransformers().size()) {
                caseIndex = 0;
                dictIndex++;
                if (dictIndex >= dictionary.size()) {
                    dictIndex = 0;
                    encoderIndex++;
                    if (encoderIndex >= PayloadTransformerFactory.getEncodingTransformers().size()) {
                        hasNext = false;
                    }
                }
            }
            
            return result;
        }
    }
}
