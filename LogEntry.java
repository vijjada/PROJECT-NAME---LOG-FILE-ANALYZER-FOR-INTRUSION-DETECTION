package logfileanalyzer;

public class LogEntry {
    private String ipAddress;
    private String timestamp;
    private String httpMethod;
    private String url;
    private int statusCode;

    public LogEntry(String ipAddress, String timestamp, String httpMethod, String url, int statusCode) {
        this.ipAddress = ipAddress;
        this.timestamp = timestamp;
        this.httpMethod = httpMethod;
        this.url = url;
        this.statusCode = statusCode;
    }

    // Getter methods for intrusion detection
    public String getIpAddress() {
        return ipAddress;
    }

    public String getUrl() {
        return url;
    }

    public String getTimestamp() {
        return timestamp;
    }

    public String getHttpMethod() {
        return httpMethod;
    }

    public int getStatusCode() {
        return statusCode;
    }

    public void display() {
        System.out.println("IP: " + ipAddress
            + " | Time: " + timestamp
            + " | Method: " + httpMethod
            + " | URL: " + url
            + " | Status: " + statusCode);
    }
}
