package authenticationService;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

/**
 *
 * @author Lucas Penha de Moura - 1208977
 */
public class Encode {

    /**
     * @param msg
     * @param key
     * @return mesnagem encriptada
     */
    public static String encode(String msg, String key) {
        Cipher cipher;

        try {
            cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            byte[] mensagem = msg.getBytes();

            byte[] chave = key.getBytes();

            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(chave, "AES"));
            byte[] encrypted = cipher.doFinal(mensagem);

            return DatatypeConverter.printHexBinary(encrypted);

        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        }

        return "";
    }

    public static String decode(String msg, String key) {
        Cipher cipher;

        try {
            cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            byte[] mensagem = DatatypeConverter.parseHexBinary(msg);

            byte[] chave = key.getBytes();

            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(chave, "AES"));

            byte[] decrypted = cipher.doFinal(mensagem);

            return new String(decrypted);

        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        }

        return "";
    }

}
