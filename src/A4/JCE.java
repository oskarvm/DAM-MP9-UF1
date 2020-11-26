package A4;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import static A4.Xifrar.*;

public class JCE {
    public static void main(String[] args) throws IOException {

        System.out.println("");
        System.out.println("-----------");
        System.out.println("");

        //1.5 Xifrar i desxifrar un text en clar amb una clau generada amb el codi 1.1.1
        String msg1 = "Xifran i desxifran";
        SecretKey sk1 = keygenKeyGeneration(256);
        byte[] msgxifrat1 = encryptData(sk1, msg1.getBytes());
        byte[] msgdesxifrat1 = decryptData(sk1, msgxifrat1);

        String s = new String(msgdesxifrat1);
        System.out.println(s);

        System.out.println("");
        System.out.println("-----------");
        System.out.println("");

        //1.6 Xifrar i desxifrar un text en clar amb una clau (codi 1.1.2) generada a partir de la paraula de pas.
        String msg2 = "Xifran i desxifran amb contrasenya";
        String passwd = "contrasenya";
        SecretKey sk2 = passwordKeyGeneration(passwd, 128);

        byte[] msgxifrat2 = encryptData(sk2, msg2.getBytes());
        byte[] msgdesxifrat2 = decryptData(sk2, msgxifrat2);

        String l = new String(msgdesxifrat2);
        System.out.println(l);

        System.out.println("");
        System.out.println("-----------");
        System.out.println("");

        //1.7 Prova alguns dels mètodes que proporciona la classe SecretKey
        System.out.println(sk1.getEncoded());
        System.out.println(sk1.getAlgorithm());
        System.out.println(sk1.getFormat());

        System.out.println("");
        System.out.println("-----------");
        System.out.println("");


        //2
        Path textxifrat = Paths.get("textamagat");
        Path claus = Paths.get("clausA4.txt");

        byte[] textoenbytes = Files.readAllBytes(textxifrat);
        List<String> clausLlista = Files.readAllLines(claus);

        int i = 0;
        boolean correcte = false;

        while (!correcte){

            try {
                SecretKey cp = passwordKeyGeneration(clausLlista.get(i), 128);
                byte[] result = decryptData(cp, textoenbytes);
                System.out.println(result.toString());

                System.out.println(clausLlista.get(i));
                System.out.println(new String(decryptData(cp, textoenbytes)));
                correcte = true;
            }catch (Exception BadPaddingException){
                i++;
                System.out.println("Contrasenya incorrecta");
            }

        }

        System.out.println("");
        System.out.println("-----------");
        System.out.println("");

        //1.8 Desxifra el text del punt 6 i comprova que donant una paraula de pas incorrecte salta l'excepció BadPaddingException
        //He posat el 1.8 al final perque el BadPaddingException trenca el programa
        String msg3 = "Xifran i desxifran amb contrasenya y error";
        String passwd3 = "otra";
        SecretKey sk3 = passwordKeyGeneration(passwd3, 128);

        byte[] msgxifrat3 = encryptData(sk2, msg3.getBytes());
        byte[] msgdesxifrat3 = decryptData(sk3, msgxifrat3);

        String l3 = new String(msgdesxifrat3);
        System.out.println(l3);


    }
}