package logfileanalyzer;
public class SSHLogEntry {
    private String timestamp;
    private String eventType;
    private String username;
    private String ipAddress;

    public SSHLogEntry(String timestamp, String eventType, String username, String ipAddress) {
        this.timestamp = timestamp;
        this.eventType = eventType;
        this.username = username;
        this.ipAddress = ipAddress;
    }

    // Getter methods for intrusion detection
    public String getTimestamp() {
        return timestamp;
    }

    public String getEventType() {
        return eventType;
    }

    public String getUsername() {
        return username;
    }

    public String getIpAddress() {
        return ipAddress;
    }

    public void display() {
        System.out.println("Time: " + timestamp
            + " | Event: " + eventType
            + " | User: " + username
            + " | IP: " + ipAddress);
    }
}
