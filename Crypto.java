import java.awt.event.KeyEvent;
import java.awt.event.KeyListener;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.file.Files;
import java.security.Key;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.swing.BoxLayout;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JProgressBar;
import javax.swing.JButton;
import javax.swing.SwingConstants;
import javax.swing.WindowConstants;

import java.awt.event.KeyAdapter;
import java.awt.Window.Type;
import java.awt.event.ActionListener;
import java.awt.event.ActionEvent;

public class Crypto {

// Iteration count for the hashing function
private static int ITERATIONS = 10000;
private static JPasswordField passwordField;
private static char[] password = {0};
/**
* Compute the strength of a password. 
* Score is based on length of the password and the type of characters it contains
* Numbers only passwords add 20 to the score
* Alphanumeric passwords add 30 to the score
* Alphanumeric(uppercase) passwords add 40 to score
* Alphanumeric(uppercase and lowercase) add 60 to score
* @param password
* @return
*/
private static int passwordStrength(char[] password) {
	int score = 0;
	String psswd = new String(password);
	score = password.length;
	if(psswd.matches(".*\\d+.*")){score = score + 20;}
	else if(psswd.matches("^(?=.*[a-z])(?=.*[0-9])[a-z0-9]+$")){score = score + 30;}
	else if(psswd.matches("^(?=.*[A-Z])(?=.*[0-9])[A-Z0-9]+$")){score = score + 40;}
	else if(psswd.matches("^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])[a-zA-Z0-9]+$")){score = score + 60;}
return score;
// TODO 
}
/**
* Displays a dialog box asking for a password.
* If encrypt is true, then the dialog should provide 
* an indication of the strength of the password.
* The method waits for the user to input a password/key
* before it returns. 
* @param encrypt
* @return
 * @wbp.parser.entryPoint
*/
private static char[] getPassword(boolean encrypt) {
	JFrame dialog = new JFrame();
	dialog.setType(Type.POPUP);
	dialog.setTitle("Encryptare 0.1");
	dialog.getContentPane().setLayout(null);
	dialog.setDefaultCloseOperation(WindowConstants.EXIT_ON_CLOSE);
	dialog.setVisible(true);
	JProgressBar progressBar = new JProgressBar();
	passwordField = new JPasswordField();
	passwordField.addKeyListener(new KeyAdapter() {
		@Override
		public void keyTyped(KeyEvent e) {
			progressBar.setValue(passwordStrength(passwordField.getPassword()));
		}
	});
	passwordField.setBounds(10, 33, 414, 20);
	dialog.getContentPane().add(passwordField);
	
	JButton btnEncrypt = new JButton("ENCRYPT");
	btnEncrypt.setBounds(10, 93, 414, 23);
	dialog.getContentPane().add(btnEncrypt);
	if(!encrypt){btnEncrypt.setText("DECRYPT");}
	
	JLabel lblInsertKey = new JLabel("Insert key");
	lblInsertKey.setHorizontalAlignment(SwingConstants.CENTER);
	lblInsertKey.setBounds(134, 11, 160, 14);
	dialog.getContentPane().add(lblInsertKey);
	
	progressBar.setBounds(10, 64, 160, 14);
	dialog.getContentPane().add(progressBar);
	
	JLabel lblKeyStrength = new JLabel("Key strength:");
	lblKeyStrength.setBounds(248, 64, 81, 14);
	dialog.getContentPane().add(lblKeyStrength);
	
	JLabel label = new JLabel("");
	label.setBounds(339, 64, 46, 14);
	dialog.getContentPane().add(label);
	while(password[0] == 0){
		btnEncrypt.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				password = passwordField.getPassword();
			}
		});
	}
	dialog.dispose();
	return password;
// TODO 
}
/**
* Performs encryption or decryption of the input based on the password and salt
* and returns the result.
* @param opmode either Cipher.ENCRYPT_MODE??or Cipher.DECRYPT_MODE
* @param password 
* @param salt
* @param input
* @return
* @throws Exception
*/
private static byte[] doCrypto(int opmode, char[] password, byte[] salt, byte[] input) throws Exception {
	// Encryption algorithm
	String algorithm = "PBEWithSHA1AndDESede";
	// Create Password-Based-Encryption Specifications from password, salt and iterations
	PBEKeySpec keySpec = new PBEKeySpec(password);
	PBEParameterSpec paramSpec = new PBEParameterSpec(salt, ITERATIONS);
	// Create SecretKeyFactory for PBEWithSHA1AndDESede algorithm
	SecretKeyFactory pswd = SecretKeyFactory.getInstance(algorithm);
	// Create key from keySpec with keyFactory
	// TODO
	SecretKey key = pswd.generateSecret(keySpec);
	// Create cipher and initialise it for encryption/decryption according to opmode
	Cipher cipher = Cipher.getInstance(algorithm);
	cipher.init(opmode, key, paramSpec); 

	return cipher.doFinal(input);

}
/**
* Returns the encrypted input with the 8-byte salt prepended.
* @param password
* @param input
* @return
* @throws Exception
*/
private static byte[] encrypt(char[] password, byte[] input) throws Exception {
	// Create a random salt of 8 bytes
	byte[] salt = new byte[8];
	// Use cryptographically strong pseudo-random number generator, not the default PRNG!
	SecureRandom random = new SecureRandom();
	random.nextBytes(salt); 
	// Call doCrypt and store results in ciphertext
	byte[] ciphertext = doCrypto(Cipher.ENCRYPT_MODE, password, salt, input); // TODO
	// Store salt and cipher text in byte array
	ByteArrayOutputStream bOut = new ByteArrayOutputStream();
	bOut.write(salt);
	bOut.write(ciphertext);
	return bOut.toByteArray();
	}
/**
* Reads the 8-byte salt from the input and returns the remaining decrypted bytes.
* @param password
* @param input
* @return
* @throws Exception
*/
private static byte[] decrypt(char[] password, byte[] input) throws Exception {
	// Read salt and cipher text
	byte [] salt = new byte[8];
	byte [] ciphertext = new byte[input.length-8];
	ByteArrayInputStream bIn = new ByteArrayInputStream(input);
	bIn.read(salt, 0, 8);
	bIn.read(ciphertext, 0, input.length-8);
	// TODO
	ciphertext = doCrypto(Cipher.DECRYPT_MODE,password,salt,ciphertext);
	return ciphertext;
	}

public static void main(String args[]) throws Exception {
 
	try { 
		if (args.length != 3 || !(args[0].equals("encrypt") || args[0].equals("decrypt")))
		{ throw new IllegalArgumentException(); }
		String operation = args[0];
		String inputFilename = args[1];
		String outputFilename = args[2];
		File inputFile = new File(inputFilename);
		File outputFile = new File(outputFilename);
		ByteArrayOutputStream bOutStream = new ByteArrayOutputStream();
		Files.copy(inputFile.toPath(), bOutStream);
		byte[] bInput = bOutStream.toByteArray();
		byte[] bOutput = "Hello".getBytes();
		// TODO
		if(operation.equals("encrypt")){bOutput = encrypt(getPassword(true), bInput);}
		else {bOutput = decrypt(getPassword(false), bInput);}
		ByteArrayInputStream bInStream = new ByteArrayInputStream(bOutput);
		Files.copy(bInStream, outputFile.toPath());
		// no need to close bOutStream or bInStream, this has no effect
		// TODO Additional exception handling required
		} catch (IllegalArgumentException e) {
			System.out.println("Arguments: encrypt <plain_file> <encrypted_file>");
			System.out.println("or         decrypt <encrypted_file> <plain_file>");
		}
	}
}
