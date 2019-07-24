import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;
import java.util.Scanner;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.lang.Math;
import java.math.BigInteger; 
import java.security.NoSuchAlgorithmException; 


public class PasswordCracker {
	
	private static Map<String, Integer> algorithms = new HashMap<String, Integer>();
	private static String algorithm = null;
	private static String dictionaryFile = null;
	
	private static void initialiseAlgorithms() {
		algorithms.put("MD5", 32);
		algorithms.put("SHA", 40);
		algorithms.put("SHA-256", 64);
	}
	
	private static String getAlgorithm(ArrayList<String> hashes) {
		Random randomSeed = new Random();
		String hash = hashes.get(Math.max(randomSeed.nextInt(Math.max((hashes.size() - 1),1)),0));
		for (Map.Entry<String, Integer> entry : algorithms.entrySet()) {
			if (entry.getValue() == hash.length()) {
				return entry.getKey();
			}
		}
		return null;
	}

	public static void main(String[] args) {
		initialiseAlgorithms();
			
		if (args.length < 1) {
			System.out.println("Invalid format. Use --help.");
			System.exit(1);
		}
		ArrayList<String> hashedInputs = new ArrayList<>();
		if (args.length > 1) {
			String hash = args[1];
			hashedInputs.add(hash);
			if (getAlgorithm(hashedInputs) == null) {
				try {
					File file = new File(hash);
					Scanner sc = new Scanner(file);
					hashedInputs.remove(0);
					while (sc.hasNextLine()) {
						hashedInputs.add(sc.nextLine());
					}
					sc.close();
				} catch (FileNotFoundException e) {
					System.out.println("The hash value is not recognised. Use --help for more info.");
					System.exit(1);
				}
			}
			algorithm = getAlgorithm(hashedInputs);
			System.out.println(algorithm);	
		}
		
		String option = args[0];
		if (option.equals("--help")) {
			System.out.println("PasswordCracker [0|1] [HASH/HASH_FILE] [DICTIONARY]");
			System.out.println("0 - Brute force attack");
			System.out.println("1 - Dictionary attack");
			System.out.println("Recognised hashes - MD5, SHA1, SHA256");
			System.out.println("Note - Brute force is not recommended for hashes of length above 6 characters");
			return;
		} else if (option.equals("0")) {
			findAlgorithm('0', hashedInputs);
		} else if (option.equals("1")) {
			if (args.length >= 3) {
				dictionaryFile = args[2];
			} else {
				dictionaryFile = "rockyou.txt";
			}
			findAlgorithm('1', hashedInputs);
		} else {
			System.out.println("The attack mode is not valid. Use --help for more info.");
			System.exit(1);	
		}
		
	}
	
	public static void findAlgorithm(int option, ArrayList<String> hashedInputs) {
		switch (option) {
		case '0': 		
			for (String hash: hashedInputs) {
				bruteForce(hash);
			}
			break;
			case '1':
				for (String hash: hashedInputs) {
					dictionaryAttack(hash);
				}
				break;
	
		}
	}
	
	public static void bruteForce(String hash) {
		StringBuilder predictedPass = new StringBuilder("");
		boolean foundHash = false;
		for (int i = 1; i <= 10; i++) {
			if (bruteForceHelper(hash, predictedPass, 0, i)) {
				foundHash = true;
				break;
			}
		}
		if (!foundHash) {
			System.out.println("Sorry couldn't find the hash");		
		}
	}
	public static boolean dictionaryAttack(String password) {
		BufferedReader bufferedReader;
		try {
			bufferedReader = 
	                new BufferedReader(new FileReader(dictionaryFile));
			String currentWord;
			while((currentWord = bufferedReader.readLine()) != null) {
				if (compareHash(password, currentWord)) {
					bufferedReader.close();
					return true;
				}
            }   
			bufferedReader.close();
			return false;
		} catch (FileNotFoundException e) {
			System.out.println("File was not found");
			return false;
		}  catch(IOException ex) {
            System.out.println("Error reading file");
            return false;
        }
	}
	
	public static boolean compareHash(String password, String currentWord) {
		String currentHash = getCurrentHash(currentWord);
		if (currentHash.equals(password) || currentHash.equals(password.toLowerCase())) {
			System.out.println("FOUND THE HASH!" + " " + currentWord);
			return true;
		} else {
			return false;
		}
	}

	public static boolean bruteForceHelper(String password, StringBuilder predicted, int pos, int length) {
		if (predicted.toString().length() == length) {
			return compareHash(password, predicted.toString());
		}
		for (char k = 'a'; k <= 'z'; k++) {
			if (pos >= predicted.length()) {
				predicted.append(k);
			} else {
				predicted.setCharAt(pos, k);
			}
			if (bruteForceHelper(password, predicted, pos + 1, length)) {
				return true;
			}
			if (pos + 1 == predicted.length()) {
				predicted.deleteCharAt(pos);	
			}
			
		}
		for (char k = 'A'; k <= 'Z'; k++) {
			if (pos >= predicted.length()) {
				predicted.append(k);
			} else {
				predicted.setCharAt(pos, k);
			}
			if (bruteForceHelper(password, predicted, pos + 1, length)) {
				return true;
			}
			if (pos + 1 == predicted.length()) {
				predicted.deleteCharAt(pos);	
			}
			
		}
		for (char k = '0'; k <= '9'; k++) {
			if (pos >= predicted.length()) {
				predicted.append(k);
			} else {
				predicted.setCharAt(pos, k);
			}
			if (bruteForceHelper(password, predicted, pos + 1, length)) {
				return true;
			}
			if (pos + 1 == predicted.length()) {
				predicted.deleteCharAt(pos);	
			}
			
		}
		return false;
	}
	
	public static String getCurrentHash(String input) 
    { 
        try { 
  
            // Static getInstance method is called with hashing MD5 
            MessageDigest md = MessageDigest.getInstance(algorithm); 
  
            // digest() method is called to calculate message digest 
            //  of an input digest() return array of byte 
            byte[] messageDigest = md.digest(input.getBytes());
  
            // Convert byte array into signum representation 
            BigInteger no = new BigInteger(1, messageDigest); 
  
            // Convert message digest into hex value 
            String hashtext = no.toString(16); 
            while (hashtext.length() < algorithms.get(algorithm)) { 
                hashtext = "0" + hashtext; 
            } 
            return hashtext; 
        }  
  
        // For specifying wrong message digest algorithms 
        catch (NoSuchAlgorithmException e) { 
            throw new RuntimeException(e); 
        } 
    } 

}
