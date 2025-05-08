package bachelor.main.IntrusionRuleGeneration;

import org.apache.commons.csv.*;


import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class CsvFilter {

    public static void main(String[] args) throws IOException {
        String inputFile = "D:\\Eclipse-workspace\\bachelor.main.IntrusionRuleGeneration2\\src\\bachelor\\main\\IntrusionRuleGeneration\\UNSW_NB15.csv";
        String outputFile = "D:\\Eclipse-workspace\\bachelor.main.IntrusionRuleGeneration2\\src\\bachelor\\main\\IntrusionRuleGeneration\\UNSW_NB15_tcp_attacks_normal.csv";
        ArrayList<String> includedAttacks = new ArrayList<>();
        includedAttacks.add("Normal");
        includedAttacks.add("Exploits");
        includedAttacks.add("Fuzzers");
        includedAttacks.add("Reconnaissance");
        includedAttacks.add("DoS");
       // includedAttacks.add("Normal");
        // Read data from the input CSV file and filter it based on the label and protocol
        List<String[]> filteredData = filterCsvByLabelAndProtocol(inputFile, "tcp",includedAttacks);

        // Write the filtered data to the output CSV file
        writeFilteredCsv(outputFile, filteredData);
    }

    private static List<String[]> filterCsvByLabelAndProtocol(String inputFile, String protocol, ArrayList<String> includedAttacks) {
        List<String[]> filteredData = new ArrayList<>();

        try (CSVParser parser = CSVParser.parse(new FileReader(inputFile), CSVFormat.DEFAULT.withFirstRecordAsHeader())) {
            // Get the index of the "attack_cat" and "proto" columns from the header
            int attackCatIndex = parser.getHeaderMap().get("attack_cat");
            int protocolIndex = parser.getHeaderMap().get("proto");

            for (CSVRecord record : parser) {
                // Get the values of the "attack_cat" and "proto" columns from the record
                String recordLabel = record.get(attackCatIndex);
                String recordProtocol = record.get(protocolIndex);

                // Check if protocol is "tcp" and label is not "normal"
                if (recordProtocol.equalsIgnoreCase(protocol) && includedAttacks.contains(recordLabel)) {
                    // Convert the record to an array of strings and add it to filteredData
                    filteredData.add(record.toMap().values().toArray(new String[0]));
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }

        return filteredData;
    }

    private static void writeFilteredCsv(String outputFile, List<String[]> filteredData) {
        try (CSVPrinter printer = new CSVPrinter(new FileWriter(outputFile), CSVFormat.DEFAULT)) {
            for (String[] record : filteredData) {
                printer.printRecord((Object[]) record);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
