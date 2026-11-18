package logfileanalyzer;
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.regex.Pattern;
import java.util.regex.Matcher;

public class SSHLogParser {
    public static void main(String[] args) {
        String logFilePath = "C:\\Users\\kasi dintakurihi\\Desktop\\sample_ssh.log.txt";
        ArrayList<SSHLogEntry> logEntries = new ArrayList<>();

        // Regex patterns for failed and accepted passwords
        String failedPattern = "(\\w+ \\d+ \\d+:\\d+:\\d+).*Failed password for(?: invalid user)? (\\w+) from (\\d{1,3}(?:\\.\\d{1,3}){3})";
        String acceptedPattern = "(\\w+ \\d+ \\d+:\\d+:\\d+).*Accepted password for (\\w+) from (\\d{1,3}(?:\\.\\d{1,3}){3})";

        Pattern failPattern = Pattern.compile(failedPattern);
        Pattern successPattern = Pattern.compile(acceptedPattern);

        try {
            BufferedReader reader = new BufferedReader(new FileReader(logFilePath));
            String line;
            int lineNumber = 0, failedCount = 0, successCount = 0;

            while ((line = reader.readLine()) != null) {
                lineNumber++;

                Matcher failMatcher = failPattern.matcher(line);
                Matcher successMatcher = successPattern.matcher(line);

                if (failMatcher.find()) {
                    String timestamp = failMatcher.group(1);
                    String username = failMatcher.group(2);
                    String ip = failMatcher.group(3);
                    SSHLogEntry entry = new SSHLogEntry(timestamp, "FAILED", username, ip);
                    logEntries.add(entry);
                    failedCount++;
                } else if (successMatcher.find()) {
                    String timestamp = successMatcher.group(1);
                    String username = successMatcher.group(2);
                    String ip = successMatcher.group(3);
                    SSHLogEntry entry = new SSHLogEntry(timestamp, "SUCCESS", username, ip);
                    logEntries.add(entry);
                    successCount++;
                } else {
                    System.out.println("Unrecognized line " + lineNumber + ": " + line);
                }
            }
            reader.close();

            System.out.println("\n=== SSH Log Parsing Complete ===");
            System.out.println("Total lines: " + lineNumber);
            System.out.println("Failed attempts: " + failedCount);
            System.out.println("Successful logins: " + successCount);

            // --- INTRUSION DETECTION: Brute-Force Attack ---
            System.out.println("\n=== BRUTE-FORCE DETECTION ===");
            HashMap<String, Integer> failedLoginCount = new HashMap<>();

            for (SSHLogEntry entry : logEntries) {
                if (entry.getEventType().equals("FAILED")) {
                    String ip = entry.getIpAddress();
                    failedLoginCount.put(ip, failedLoginCount.getOrDefault(ip, 0) + 1);
                }
            }

            boolean bruteForceDetected = false;
            for (String ip : failedLoginCount.keySet()) {
                int count = failedLoginCount.get(ip);
                if (count >= 5) {
                    System.out.println("[ALERT] Brute-force attack detected from IP: " + ip + " (" + count + " failed login attempts)");
                    bruteForceDetected = true;
                }
            }

            if (!bruteForceDetected) {
                System.out.println("No brute-force attacks detected.");
            }

            System.out.println("\n=== Parsed SSH Log Entries ===\n");
            for (SSHLogEntry entry : logEntries) {
                entry.display();
            }

        } catch (IOException e) {
            System.out.println("Error reading file: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
