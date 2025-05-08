package bachelor.main.IntrusionRuleGeneration;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

public class CsvColumnReader {
    public static void main(String[] args) throws IOException {
        String filePath = "D:\\Eclipse-workspace\\bachelor.main.IntrusionRuleGeneration2\\src\\bachelor\\main\\IntrusionRuleGeneration\\UNSW_NB15_tcp_attacks_normal.csv"; // Replace with the actual path to your CSV file
        Map<String, Integer> occurrenceMap = new HashMap<>(); // Use a String key instead of Integer
        boolean isFirstLine = true; // Flag to skip the header row

        try (BufferedReader br = new BufferedReader(new FileReader(filePath))) {
            String line;
            while ((line = br.readLine()) != null) {
                if (isFirstLine) {
                    isFirstLine = false;
                    continue; // Skip the header row
                }
                String[] tokens = line.split(",");
                if (tokens.length >43) {
                    String stringValue = tokens[43].trim(); // Extract the string value
                    occurrenceMap.put(stringValue, occurrenceMap.getOrDefault(stringValue, 0) + 1);
                }
            }
        }

        // Print the occurrences
        for (Map.Entry<String, Integer> entry : occurrenceMap.entrySet()) {
            String stringValue = entry.getKey();
            int count = entry.getValue();
            if (count > 20) {
                System.out.println(stringValue + count );
            }
        }
    }
}
