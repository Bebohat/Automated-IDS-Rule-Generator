package bachelor.main.IntrusionRuleGeneration;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Random;

public class CSVDownsampler {

    public static void main(String[] args) {
        // Path to the input CSV file
        String inputFile = "D:\\Eclipse-workspace\\bachelor.main.IntrusionRuleGeneration2\\src\\bachelor\\main\\IntrusionRuleGeneration\\UNSW_NB15_tcp_attacks.csv";
        // Path to the output CSV file
        String outputFile = "D:\\Eclipse-workspace\\bachelor.main.IntrusionRuleGeneration2\\src\\bachelor\\main\\IntrusionRuleGeneration\\UNSW_NB15_tcp_attacks2.csv";

        // Target number of entries for downsampling
        int targetEntries = 2281;

        try (BufferedReader reader = new BufferedReader(new FileReader(inputFile));
             BufferedWriter writer = new BufferedWriter(new FileWriter(outputFile))) {

            // Skip header line
            reader.readLine();
            
            // Initialize lists to hold lines for each category
            List<String> reconnaissanceLines = new ArrayList<>();
            List<String> exploitLines = new ArrayList<>();
            List<String> dosLines = new ArrayList<>();
            List<String> fuzzerLines = new ArrayList<>();

            // Read lines from the CSV and separate them into category lists
            String line;
            while ((line = reader.readLine()) != null) {
                String[] parts = line.split(",");
                String category = parts[43].trim(); // Assuming category is at index 39 (adjust accordingly)
                switch (category) {
                    case "Reconnaissance":
                        reconnaissanceLines.add(line);
                        break;
                    case "Exploits":
                        exploitLines.add(line);
                        break;
                    case "DoS":
                        dosLines.add(line);
                        break;
                    case "Fuzzers":
                        fuzzerLines.add(line);
                        break;
                }
            }

            // Shuffle each category list
            Collections.shuffle(reconnaissanceLines);
            Collections.shuffle(exploitLines);
            Collections.shuffle(dosLines);
            Collections.shuffle(fuzzerLines);

            // Select a subset of each category list
            List<String> downsampledLines = new ArrayList<>();
            downsampledLines.addAll(reconnaissanceLines.subList(0, Math.min(reconnaissanceLines.size(), targetEntries)));
            downsampledLines.addAll(exploitLines.subList(0, Math.min(exploitLines.size(), targetEntries)));
            downsampledLines.addAll(dosLines.subList(0, Math.min(dosLines.size(), targetEntries)));
            downsampledLines.addAll(fuzzerLines.subList(0, Math.min(fuzzerLines.size(), targetEntries)));

            // Write the downsampled lines to the output file
            for (String downsampledLine : downsampledLines) {
                writer.write(downsampledLine + "\n");
            }

            System.out.println("Downsampling complete. Output written to " + outputFile);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
