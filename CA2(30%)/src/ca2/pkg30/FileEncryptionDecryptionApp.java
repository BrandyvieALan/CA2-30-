//https://www.quickprogrammingtips.com/java/how-to-encrypt-and-decrypt-data-in-java-using-aes-algorithm.html
import java.io.*;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Scanner;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class FileEncryptionDecryptionApp {

    public static void main(String[] args) {
        System.out.println("Welcome to the File Encryption/Decryption Application!");
        menuSystem();
    }

    // Display the menu
    public static void displayMenu() {
        System.out.println("\n===== File Encryption/Decryption Application =====");
        System.out.println("1. Encrypt a File");
        System.out.println("2. Decrypt a File");
        System.out.println("3. Quit");
        System.out.println("=================================================");
    }

    // Menu system
    public static void menuSystem() {
        Scanner scanner = new Scanner(System.in);
        boolean running = true;

        while (running) {
            displayMenu();
            System.out.print("Enter your choice (1-3): ");

            String input = scanner.nextLine().trim();
            try {
                int choice = Integer.parseInt(input);

                if (choice == 1) {
                    encryptFile();
                } else if (choice == 2) {
                    decryptFile();
                } else if (choice == 3) {
                    System.out.println("\n[INFO] Exiting the application. Goodbye!");
                    running = false; // Stop the program
                } else {
                    System.out.println("Invalid choice! Please enter a number between 1 and 3.");
                }
            } catch (NumberFormatException e) {
                System.out.println("Invalid input! Please enter a valid number.");
            }
        }

        scanner.close(); // Close the scanner
    }

    // Encrypt file method
    //this is where this part the code got inspired from
    //https://www.quickprogrammingtips.com/java/how-to-encrypt-and-decrypt-data-in-java-using-aes-algorithm.html
    public static void encryptFile() {
        Scanner scanner = new Scanner(System.in);
        System.out.print("Enter the filename to encrypt: ");
        String fileName = scanner.nextLine().trim();

        File inputFile = new File(fileName);
        if (!inputFile.exists()) {
            System.out.println("[ERROR] File not found: " + fileName);
            return;
        }

        try {
            // Generate a random AES key
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(128, new SecureRandom()); // Simplified to 128-bit key
            SecretKey secretKey = keyGen.generateKey();

            // Read file content
            byte[] fileContent = readFile(inputFile);

            // Encrypt the file content
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            byte[] encryptedData = cipher.doFinal(fileContent);

            // Write encrypted data to a new file
            File encryptedFile = new File("ciphertext.txt");
            writeFile(encryptedFile, encryptedData);
            System.out.println("[INFO] File encrypted successfully!");
            System.out.println("[INFO] Encrypted data written to: ciphertext.txt");

            // Display the encryption key
            String encodedKey = Base64.getEncoder().encodeToString(secretKey.getEncoded());
            System.out.println("[INFO] Encryption Key (Save this securely!): " + encodedKey);

        } catch (Exception e) {
            System.out.println("[ERROR] An error occurred while encrypting the file.");
            e.printStackTrace();
        }
    }

    // Decrypt file method
    //https://stackoverflow.com/questions/18228579/how-to-create-a-secure-random-aes-key-in-java
    //https://stackoverflow.com/questions/42249072/click-only-one-random-button-from-the-true-condition-response-jquery-javascript/42249230#42249230

    public static void decryptFile() {
        Scanner scanner = new Scanner(System.in);
        System.out.print("Enter the filename to decrypt: ");
        String fileName = scanner.nextLine().trim();

        File inputFile = new File(fileName);
        if (!inputFile.exists()) {
            System.out.println("[ERROR] File not found: " + fileName);
            return;
        }

        System.out.print("Enter the decryption key: ");
        String encodedKey = scanner.nextLine().trim();

        try {
            // Decode the Base64 key
            byte[] decodedKey = Base64.getDecoder().decode(encodedKey);
            SecretKeySpec secretKey = new SecretKeySpec(decodedKey, "AES");

            // Read the encrypted file content
            byte[] encryptedData = readFile(inputFile);

            // Decrypt the file content
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            byte[] decryptedData = cipher.doFinal(encryptedData);

            // Write decrypted data to a new file
            File decryptedFile = new File("plaintext.txt");
            writeFile(decryptedFile, decryptedData);
            System.out.println("[INFO] File decrypted successfully!");
            System.out.println("[INFO] Decrypted data written to: plaintext.txt");

        } catch (Exception e) {
            System.out.println("[ERROR] An error occurred during decryption. Please check your key.");
            e.printStackTrace();
        }
    }

    // Helper method to read a file
    private static byte[] readFile(File file) throws IOException {
        try (FileInputStream fis = new FileInputStream(file);
             ByteArrayOutputStream bos = new ByteArrayOutputStream()) {
            byte[] buffer = new byte[1024];
            int bytesRead;
            while ((bytesRead = fis.read(buffer)) != -1) {
                bos.write(buffer, 0, bytesRead);
            }
            return bos.toByteArray();
        }
    }

    // Helper method to write to a file
    private static void writeFile(File file, byte[] data) throws IOException {
        try (FileOutputStream fos = new FileOutputStream(file)) {
            fos.write(data);
        }
    }
}
