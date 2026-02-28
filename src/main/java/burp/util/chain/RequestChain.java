package burp.util.chain;

import java.util.ArrayList;
import java.util.List;

public class RequestChain {
    
    private String id;
    private String name;
    private String description;
    private List<ChainNode> nodes;
    private ChainStatus status;
    private long createdTime;
    
    public enum ChainStatus {
        PENDING,
        RUNNING,
        COMPLETED,
        FAILED,
        PARTIAL
    }
    
    public RequestChain() {
        this.nodes = new ArrayList<>();
        this.status = ChainStatus.PENDING;
        this.createdTime = System.currentTimeMillis();
    }
    
    public RequestChain(String id, String name) {
        this();
        this.id = id;
        this.name = name;
    }
    
    public void addNode(ChainNode node) {
        if (node != null) {
            nodes.add(node);
        }
    }
    
    public void removeNode(String nodeId) {
        nodes.removeIf(n -> n.getId().equals(nodeId));
    }
    
    public ChainNode getNode(int index) {
        if (index >= 0 && index < nodes.size()) {
            return nodes.get(index);
        }
        return null;
    }
    
    public ChainNode getNextPendingNode() {
        for (ChainNode node : nodes) {
            if (node.getStatus() == ChainNode.NodeStatus.PENDING) {
                return node;
            }
        }
        return null;
    }
    
    public List<ChainNode> getNodes() {
        return new ArrayList<>(nodes);
    }
    
    public void setNodes(List<ChainNode> nodes) {
        this.nodes = nodes != null ? new ArrayList<>(nodes) : new ArrayList<>();
    }
    
    public int getNodeCount() {
        return nodes.size();
    }
    
    public boolean hasNodes() {
        return !nodes.isEmpty();
    }
    
    public void updateStatus() {
        int pending = 0, running = 0, completed = 0, failed = 0;
        
        for (ChainNode node : nodes) {
            switch (node.getStatus()) {
                case PENDING: pending++; break;
                case RUNNING: running++; break;
                case COMPLETED: completed++; break;
                case FAILED: failed++; break;
            }
        }
        
        if (failed > 0 && completed + failed == nodes.size()) {
            status = ChainStatus.FAILED;
        } else if (failed > 0 && completed > 0) {
            status = ChainStatus.PARTIAL;
        } else if (completed == nodes.size()) {
            status = ChainStatus.COMPLETED;
        } else if (running > 0) {
            status = ChainStatus.RUNNING;
        } else {
            status = ChainStatus.PENDING;
        }
    }
    
    public String getId() {
        return id;
    }
    
    public void setId(String id) {
        this.id = id;
    }
    
    public String getName() {
        return name;
    }
    
    public void setName(String name) {
        this.name = name;
    }
    
    public String getDescription() {
        return description;
    }
    
    public void setDescription(String description) {
        this.description = description;
    }
    
    public ChainStatus getStatus() {
        return status;
    }
    
    public void setStatus(ChainStatus status) {
        this.status = status;
    }
    
    public long getCreatedTime() {
        return createdTime;
    }
    
    public void setCreatedTime(long createdTime) {
        this.createdTime = createdTime;
    }
    
    @Override
    public String toString() {
        return "RequestChain{" +
                "id='" + id + '\'' +
                ", name='" + name + '\'' +
                ", nodeCount=" + nodes.size() +
                ", status=" + status +
                '}';
    }
}
