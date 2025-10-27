package logfileanalyzer;
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.regex.Pattern;
import java.util.regex.Matcher;

public class ApacheLogParser {
    public static void main(String[] args) {
        String logFilePath = "C:\\Users\\kasi dintakurihi\\Desktop\\sample_apache.log.txt";

        ArrayList<LogEntry> logEntries = new ArrayList<>();

        String logPattern = "(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}).*?\\[(.*?)\\].*?\"(GET|POST|PUT|DELETE) (.*?) HTTP.*?\" (\\d{3})";
        Pattern pattern = Pattern.compile(logPattern);

        try {
            BufferedReader reader = new BufferedReader(new FileReader(logFilePath));
            String line;
            int lineNumber = 0, successCount = 0, failCount = 0;
            
            while ((line = reader.readLine()) != null) {
                lineNumber++;
                Matcher matcher = pattern.matcher(line);
                if (matcher.find()) {
                    String ip = matcher.group(1);
                    String time = matcher.group(2);
                    String method = matcher.group(3);
                    String url = matcher.group(4);
                    int status = Integer.parseInt(matcher.group(5));
                    LogEntry entry = new LogEntry(ip, time, method, url, status);
                    logEntries.add(entry);
                    successCount++;
                } else {
                    System.out.println("Failed to parse line " + lineNumber + ": " + line);
                    failCount++;
                }
            }
            reader.close();

            System.out.println("\n=== Apache Log Parsing Complete ===");
            System.out.println("Total lines: " + lineNumber);
            System.out.println("Successfully parsed: " + successCount);
            System.out.println("Failed to parse: " + failCount);

            // --- INTRUSION DETECTION: Port Scan ---
            System.out.println("\n=== PORT SCAN DETECTION ===");
            HashMap<String, HashSet<String>> ipToUrls = new HashMap<>();

            for (LogEntry entry : logEntries) {
                String ip = entry.getIpAddress();
                ipToUrls.putIfAbsent(ip, new HashSet<>());
                ipToUrls.get(ip).add(entry.getUrl());
            }

            boolean portScanDetected = false;
            for (String ip : ipToUrls.keySet()) {
                int uniqueUrls = ipToUrls.get(ip).size();
                if (uniqueUrls >= 5) {
                    System.out.println("[ALERT] Port scan suspected from IP: " + ip + " (accessed " + uniqueUrls + " different URLs)");
                    portScanDetected = true;
                }
            }

            if (!portScanDetected) {
                System.out.println("No port scans detected.");
            }

            // --- INTRUSION DETECTION: DoS Attack ---
            System.out.println("\n=== DOS ATTACK DETECTION ===");
            HashMap<String, Integer> requestCount = new HashMap<>();

            for (LogEntry entry : logEntries) {
                String ip = entry.getIpAddress();
                requestCount.put(ip, requestCount.getOrDefault(ip, 0) + 1);
            }

            boolean dosDetected = false;
            for (String ip : requestCount.keySet()) {
                int count = requestCount.get(ip);
                if (count >= 10) {
                    System.out.println("[ALERT] Possible DoS attack from IP: " + ip + " (" + count + " requests)");
                    dosDetected = true;
                }
            }

            if (!dosDetected) {
                System.out.println("No DoS attacks detected.");
            }

            System.out.println("\n=== Parsed Log Entries ===\n");
            for (LogEntry entry : logEntries) {
                entry.display();
            }

        } catch (IOException e) {
            System.out.println("Error reading file: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
