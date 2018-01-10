package authenticationService;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author Lucas Penha de Moura - 1208977
 */
public class AuthenticationService {

    private String K_C, ID_C, ID_S, T_R, N1, M2, K_C_TGS;
    private String chaveEncript, chave1, K_TGS, TGT;

    public void startAS() throws IOException {

        String clientMessage;

//        ServerSocket welcomeSocket = new ServerSocket(6789); 
        ServerSocket welcomeSocket = new ServerSocket();
        welcomeSocket.setReuseAddress(true);
        welcomeSocket.bind(new InetSocketAddress(12345));

        while (true) {

            Socket connectionSocket = welcomeSocket.accept();
            BufferedReader messageFromClient = new BufferedReader(new InputStreamReader(connectionSocket.getInputStream()));

            DataOutputStream messageToClient = new DataOutputStream(connectionSocket.getOutputStream());
            clientMessage = messageFromClient.readLine();

            //leKc();
            opemMsg(clientMessage);//feito
            K_C_TGS_gen();//eh preciso gerar esta chava antes de criar M2
            messageGen();//cria M2

            messageToClient.writeBytes(M2 + '\n');

        }
    }

    public void messageGen() throws IOException {

        String M2_Pt1 = K_C_TGS + ";" + N1;
        String M2_Pt1_encrypt = Encode.encode(M2_Pt1, K_C);

       K_TGS = newKeyGen("KTGS");//cria o K_TGS e salva em um arquivo -MELHOR ISSO

        //TICKET 1
        String M2_Pt2 = ID_C + ";" + T_R + ";" + K_C_TGS;
        TGT = Encode.encode(M2_Pt2, K_TGS); //TGT é criptografado com a chave de TGS
        System.out.println("T_C_TGS = " + TGT);

        M2 = M2_Pt1_encrypt + ";" + TGT;

    }

    public void K_C_TGS_gen() {
        K_C_TGS = KeyGen.newKey();
        System.out.println("K_C_TGS2 = " + K_C_TGS);
    }

    public void opemMsg(String mensagem) {
       
        String splitMsg[] = mensagem.split(";");
        ID_C = splitMsg[0];
        
        K_C = newKeyGen("KC"+ID_C);
        System.out.println("ID_C: " + ID_C);
        
        System.out.println("KC em AS: " + K_C);

        ID_S = splitMsg[1];
        System.out.println("ID_S: " + ID_S);

        T_R = splitMsg[2];
        System.out.println("T_R: " + T_R);

        N1 = splitMsg[3];
        System.out.println("N1: " + N1);

    }


    public String newKeyGen(String passwd) {
        String retorno = null;
        MessageDigest md;
        try {
            md = MessageDigest.getInstance("SHA-256");
            md.update(passwd.getBytes());

            byte byteData[] = md.digest();

            //convert the byte to hex format method 1
            StringBuilder hash = new StringBuilder();
            for (int i = 0; i < byteData.length; i++) {
                hash.append(Integer.toString((byteData[i] & 0xff) + 0x100, 16).substring(1));
            }

            //System.out.println("Hex format : " + sb.toString());
            retorno = hash.toString();
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(AuthenticationService.class.getName()).log(Level.SEVERE, null, ex);
        }

        return retorno.substring(0, 16);
    }
}
