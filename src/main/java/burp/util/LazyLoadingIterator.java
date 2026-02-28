package burp.util;

import java.util.Iterator;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.function.Function;

public class LazyLoadingIterator<T> implements Iterator<T> {
    
    private final Iterator<String> sourceIterator;
    private final Function<String, T> transformer;
    private final int maxItems;
    private int currentIndex;
    private T nextItem;
    private boolean hasNextComputed;
    
    public LazyLoadingIterator(List<String> sourceList, Function<String, T> transformer) {
        this(sourceList, transformer, Integer.MAX_VALUE);
    }
    
    public LazyLoadingIterator(List<String> sourceList, Function<String, T> transformer, int maxItems) {
        if (sourceList == null) {
            this.sourceIterator = java.util.Collections.emptyIterator();
        } else {
            this.sourceIterator = sourceList.iterator();
        }
        this.transformer = transformer != null ? transformer : s -> (T) s;
        this.maxItems = maxItems > 0 ? maxItems : Integer.MAX_VALUE;
        this.currentIndex = 0;
        this.hasNextComputed = false;
    }
    
    @Override
    public boolean hasNext() {
        if (hasNextComputed) {
            return nextItem != null;
        }
        
        if (currentIndex >= maxItems) {
            nextItem = null;
            hasNextComputed = true;
            return false;
        }
        
        while (sourceIterator.hasNext()) {
            String source = sourceIterator.next();
            try {
                nextItem = transformer.apply(source);
                if (nextItem != null) {
                    currentIndex++;
                    hasNextComputed = true;
                    return true;
                }
            } catch (Exception e) {
                // Skip invalid items
            }
        }
        
        nextItem = null;
        hasNextComputed = true;
        return false;
    }
    
    @Override
    public T next() {
        if (!hasNext()) {
            throw new NoSuchElementException();
        }
        
        T result = nextItem;
        nextItem = null;
        hasNextComputed = false;
        return result;
    }
    
    public int getCurrentIndex() {
        return currentIndex;
    }
    
    public int getMaxItems() {
        return maxItems;
    }
    
    public static <T> LazyLoadingIterator<T> fromList(List<String> list, Function<String, T> transformer) {
        return new LazyLoadingIterator<>(list, transformer);
    }
    
    public static <T> LazyLoadingIterator<T> fromList(List<String> list, Function<String, T> transformer, int maxItems) {
        return new LazyLoadingIterator<>(list, transformer, maxItems);
    }
}
