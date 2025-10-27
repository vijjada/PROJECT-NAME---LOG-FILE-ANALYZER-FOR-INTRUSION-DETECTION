package logfileanalyzer;

import java.util.regex.Pattern;
import java.util.regex.Matcher;

public class RegexLearning {
    public static void main(String[] args) {
        
        // Sample log line
        String logLine = "192.168.2.20 - - [28/Jul/2006:10:27:10 -0300] \"GET /cgi-bin/try/ HTTP/1.0\" 200 3395";
        
        // Example 1: Extract IP address
        // Pattern: digits.digits.digits.digits
        String ipPattern = "(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})";
        Pattern pattern1 = Pattern.compile(ipPattern);
        Matcher matcher1 = pattern1.matcher(logLine);
        
        if (matcher1.find()) {
            System.out.println("IP Address: " + matcher1.group(1));
        }
        
        // Example 2: Extract timestamp
        String timestampPattern = "\\[(.*?)\\]";
        Pattern pattern2 = Pattern.compile(timestampPattern);
        Matcher matcher2 = pattern2.matcher(logLine);
        
        if (matcher2.find()) {
            System.out.println("Timestamp: " + matcher2.group(1));
        }
        
        // Example 3: Extract HTTP method (GET, POST, etc.)
        String methodPattern = "\"(GET|POST|PUT|DELETE)";
        Pattern pattern3 = Pattern.compile(methodPattern);
        Matcher matcher3 = pattern3.matcher(logLine);
        
        if (matcher3.find()) {
            System.out.println("HTTP Method: " + matcher3.group(1));
        }
        
        // Example 4: Extract status code
        String statusPattern = "\" (\\d{3}) ";
        Pattern pattern4 = Pattern.compile(statusPattern);
        Matcher matcher4 = pattern4.matcher(logLine);
        
        if (matcher4.find()) {
            System.out.println("Status Code: " + matcher4.group(1));
        }
    }
}
