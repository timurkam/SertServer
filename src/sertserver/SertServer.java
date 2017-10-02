
package sertserver;


import java.io.*;
import java.net.*;
import java.security.*;
import java.security.spec.*;
import java.util.Base64;
import java.util.Date;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.*;
import javax.swing.JOptionPane;
import javax.xml.bind.DatatypeConverter;
import java.lang.Object;



public class SertServer extends Thread{
    Socket s;
    int num;

    OwnCert owc;

    static PrivateKey priv;
    static PublicKey pub;
    static PublicKey pubcli;
    static SecretKey secretkey ;


    static KeyPair keys;

    static File privateKeyFile = new File("serv//private.key");
    static File publicKeyFile = new File("serv//public.key");
    int socket=3128;
    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        // TODO code application logic here
        try
        {
            int i = 0; // счётчик подключений
            if (!privateKeyFile.exists()) {
                generateKey();
                createKeyFiles();
            }
            else{
                priv = restorePrivate();
                pub = restorePublic(fileToKey("serv//public.key"));

            }
            secretkey = KeyGenerator.getInstance("DES").generateKey();
            // Используем скоет на localhost для DSA, порт 3128
            ServerSocket server = new ServerSocket(3128, 0,
                    InetAddress.getByName("localhost"));

            System.out.println("Сервер онлайн, ожидание клиента");
            System.out.println("\n\n");
            // слушаем порт
            while(true)
            {
                // ждём нового подключения, после чего запускаем обработку клиента
                // в новый вычислительный поток и увеличиваем счётчик на единичку
                new SertServer(i, server.accept());
                i++;
            }
        }
        catch(Exception e)
        {
            Logger.getLogger(SertServer.class.getName()).log(Level.SEVERE, null, e);
        } // вывод исключений
    }

    public SertServer(int num, Socket s)
    {
        // копируем данные
        this.num = num;
        this.s = s;

        // и запускаем новый вычислительный поток (см. ф-ю run())
        setDaemon(true);
        setPriority(NORM_PRIORITY);
        start();
    }

    @Override
    public void run()
    {
        try
        {
            // из сокета клиента берём поток входящих данных
            DataInputStream is = new DataInputStream(s.getInputStream());
            // и оттуда же - поток данных от сервера к клиенту
            // буффер данных в 64 килобайта
            byte buf[] = new byte[64*1024];
            DataOutputStream os = new DataOutputStream(s.getOutputStream());

//------------------------------------------------------------------------------
//           Получаем открытый ключ клиента
//------------------------------------------------------------------------------

            ObjectOutputStream obOut = new ObjectOutputStream(s.getOutputStream());
            ObjectInputStream obIn = new ObjectInputStream(s.getInputStream());


            Object obj = obIn.readObject();
            pubcli = (PublicKey) obj;
            //System.out.println("Получен открытый ключ: "+pubcli.toString());
            obOut.writeObject(pub);
            obOut.flush();
            //System.out.println("Отправлен открытый ключ: "+pub.toString());
//------------------------------------------------------------------------------
//       Получаем из него объект типа PublicKey (pubstr может быть не нужен)
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
//        Шифруем строку ControlString со свежими ключами, чтобы получать
//        каждый раз разные сложно предсказуемые строк
//------------------------------------------------------------------------------

            String forEnc = "ControlString";


           String decr=desencrypt(forEnc,secretkey);
//------------------------------------------------------------------------------
//       Передаем клиенту сгенерированную строку, зашифрованную с клиентским
//       открытым ключом (проверка)
//------------------------------------------------------------------------------
            forEnc=encrypt(decr,pubcli);
            //PrintWriter out = new PrintWriter(s.getOutputStream(), true);
            os.writeUTF(forEnc);
            os.flush();

            //System.out.println("Посылаем шифровку клиенту: "+forEnc);

//------------------------------------------------------------------------------
//       Получаем ответ - расшифрованное сообщение
//      Если совпадает с посланным -> создаем сертификат
//------------------------------------------------------------------------------

            String decMsg = is.readUTF();

            //System.out.println("Получено зашифрованное сообщение: "+decMsg);
            decMsg=decrypt(decMsg, priv);
            //System.out.println("Получено расшифрованное сообщение: "+decMsg);
            if (decMsg.equals(decr)){

                //System.out.println("Совпадение 100%");
                //System.out.println("\n\n");

//------------------------------------------------------------------------------
//       Отправляем положительный ответ клиенту, в ответ получаем его
//       уникальное имя
//------------------------------------------------------------------------------

                os.writeUTF("Ok");
                os.flush();

                String name = "";
                name = is.readUTF();

                System.out.println("Получен домен/название: "+name);

//------------------------------------------------------------------------------
//          Заполняем текущий сертификат
//------------------------------------------------------------------------------

                owc = createCert(name);

//                wr_2_file(owc.recieveAll(),name);
//
//                System.out.println(rd_from_file(name));
                System.out.println("+++++++++++++++++");
                System.out.println(owc.recieveAll());
                System.out.println("+++++++++++++++++");
//------------------------------------------------------------------------------
//          Хэшируем сертификат
//------------------------------------------------------------------------------

                String dig = getDigest(owc.recieveAll());

                System.out.println("Производится хеширование");
//
//                System.out.println(dig);

//------------------------------------------------------------------------------
//          Подписываем
//------------------------------------------------------------------------------

                byte[] certsign = getSign(dig,priv);
//                System.out.println(verifySign(dig,certsign,pub));

//------------------------------------------------------------------------------
//          Пишем в файл сертификат+подпись в Hex-формате - сертификат
//------------------------------------------------------------------------------

                wr_2_file(owc.recieveAll()+"\n"+byte2Hex(certsign),name);

//------------------------------------------------------------------------------
//          Отправляем клиенту сообщения
//          1. Длина сертификата в байтах
//          2. Сертификат
//          3. Длина подписи в байтах
//          4. Подпись
//------------------------------------------------------------------------------

                byte[] certEnc = getEncB64(owc.recieveAll());
 //               System.out.println("Длина сертификата в байтах:");
                os.writeInt(certEnc.length); //1.
                os.flush();

                os.write(certEnc);//2.
                os.flush();
                //System.out.println("2");
                os.writeInt(certsign.length);//3.
                os.flush();
                //System.out.println("3");

                os.write(certsign);//4.
                os.flush();
                //System.out.println("4");

                String answer = is.readUTF(); // получаем ответ
                System.out.println("\n\n");
                if (answer.equals("Ok")) System.out.println("Связь успешно установлена, данные переданы. Пишите.");
                else System.out.println("Подписи не совпадают. ОШИБКА.");
                String line;
                while (true) {
                    line = is.readUTF();
                    System.out.println("Пришло зашифрованное сообщение : " + line);
                    line=decrypt(line,priv);
                    System.out.println("Расшифрованное сообщение : " + line);
                    line=encrypt(line,pubcli);
                    System.out.println("Шифруем сообщение : " + line);
                    System.out.println("Отправка");
                    os.writeUTF(line); // отсылаем клиенту обратно ту самую строку текста.
                    os.flush(); // заставляем поток закончить передачу данных.
                    System.out.println("Отправка окончена");
                    System.out.println("Ждем");
                    System.out.println();
                    //list.add(new ClientHandler(workingSocket/*, status*/));
                }
            }
            else{
                System.out.println("Ошибка проверки хоста");
                System.out.println("-----------------------------------------");
                os.writeUTF("No");
                os.flush();
            }

            // завершаем соединение
            os.close();
            s.close();

            System.out.println("");
        }
        catch (IOException ex)
        {
            Logger.getLogger(SertServer.class.getName()).log(Level.SEVERE, null, ex);
        }
        catch (NoSuchAlgorithmException ex)
        {
            Logger.getLogger(SertServer.class.getName()).log(Level.SEVERE, null, ex);
        }
        catch(InvalidKeySpecException ex)
        {
            Logger.getLogger(SertServer.class.getName()).log(Level.SEVERE, null, ex);
        }
        catch(Exception ex)
        {
            Logger.getLogger(SertServer.class.getName()).log(Level.SEVERE, null, ex);
        } // вывод исключений
    }


    //УСТАНОВКА ЦИФРОВОЙ ПОДПИСИ MD2/RSA
    private OwnCert createCert(String nm) throws UnsupportedEncodingException{
        OwnCert oc = new OwnCert();
        oc.setSubj(nm);
        oc.setIssuer("Localhost");
        oc.setOkey(byte2Hex(pubcli.getEncoded()));
        oc.setSingAlg("MD2/RSA");
        Date d = new Date();
        oc.setDateBefore(d.toString());

        Date dplus = new Date();
        oc.setDateAfter(dplus.toString());



        return oc;
    }
    //УСТАНОВКА ЦИФРОВОЙ ПОДПИСИ
    static public String getDigest(String input) throws NoSuchAlgorithmException, UnsupportedEncodingException{
        MessageDigest d = MessageDigest.getInstance("md2");
        d.reset();
        d.update(input.getBytes());
        return byte2Hex(d.digest());//buf = encrypt(hash,pub);
    }

    public byte[] getSign(String input,PrivateKey pkey) throws Exception{

        Signature signature = Signature.getInstance("MD2withRSA");

        signature.initSign( pkey);
        signature.update(input.getBytes());
        byte[] res = signature.sign();
        return res;
    }


    void wr_2_file(String s,String path) throws FileNotFoundException, IOException{
        byte[] base64data = getEncB64(s);

        File fcheck = new File("serv/"+path+".crt");
        if (fcheck.exists()) fcheck.delete();

        FileOutputStream fs = new FileOutputStream("serv/"+path+".crt");
        fs.write(base64data, 0, base64data.length);

        fs.close();
    }

    String rd_from_file(String path) throws FileNotFoundException, IOException{

        FileInputStream fs = new FileInputStream("serv/"+path+".crt");
        byte[] base64data = new byte[fs.available()];
        fs.read(base64data, 0, fs.available());
        fs.close();

        return getDecB64(base64data);
    }

    byte[] getEncB64(String s){
        return Base64.getEncoder().encode(s.getBytes());
    }

    String getDecB64(byte[] base64data) throws UnsupportedEncodingException{
        return new String(Base64.getDecoder().decode(base64data), "UTF-8");
    }

    static public void generateKey() {
        try {
            final KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(1024, new SecureRandom());
            keys = keyGen.generateKeyPair();

            pub = keys.getPublic();
            priv = keys.getPrivate();
        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    static private void createKeyFiles() throws IOException{
        String dir = new File("").getAbsolutePath()+"/serv";
        //System.out.println(dir);
        File f;
        f = new File(dir);
        if (!f.isDirectory()) if (!f.mkdir()) JOptionPane.showMessageDialog(null, "Невозможно создать папку");

        if (privateKeyFile.getParentFile() != null) {
            privateKeyFile.getParentFile().mkdirs();
        }
        privateKeyFile.createNewFile();

        if (publicKeyFile.getParentFile() != null) {
            publicKeyFile.getParentFile().mkdirs();
        }
        publicKeyFile.createNewFile();

        BufferedWriter pubOut = new BufferedWriter(new OutputStreamWriter(new FileOutputStream(publicKeyFile)));
        pubOut.write(byte2Hex(pub.getEncoded()));
        pubOut.flush();
        pubOut.close();


        BufferedWriter privOut = new BufferedWriter(new OutputStreamWriter(new FileOutputStream(privateKeyFile)));
        privOut.write(byte2Hex(priv.getEncoded()));
        privOut.flush();
        privOut.close();

    }

    private static byte[] fileToKey(String file) throws IOException {
        BufferedReader pubIn = new BufferedReader(new InputStreamReader(new FileInputStream(file)));
        StringBuilder sb = new StringBuilder();
        String tmp;
        do {
            tmp = pubIn.readLine();
            if (tmp != null) sb.append(tmp);
        } while (tmp != null);
        return hex2Byte(sb.toString());
    }

    private static PublicKey restorePublic(byte[] key) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(key);
        return keyFactory.generatePublic(publicKeySpec);
    }

    private static PrivateKey restorePrivate() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(fileToKey("serv//private.key"));
        return keyFactory.generatePrivate(privateKeySpec);
    }

    static String encrypt(String str , PublicKey pub) throws UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException {

        Cipher ecipher;
        ecipher = Cipher.getInstance("RSA");

        ecipher.init(Cipher.ENCRYPT_MODE, pub);
        byte[] utf8 = str.getBytes("UTF8");
        byte[] enc = ecipher.doFinal(utf8);
        return new sun.misc.BASE64Encoder().encode(enc);
    }
    static String desencrypt(String str , SecretKey pub) throws UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException {

        Cipher ecipher;
        ecipher = Cipher.getInstance("DES");

        ecipher.init(Cipher.ENCRYPT_MODE, pub);
        byte[] utf8 = str.getBytes("UTF8");
        byte[] enc = ecipher.doFinal(utf8);
        return new sun.misc.BASE64Encoder().encode(enc);
    }
    static String decrypt(String str, PrivateKey priv) throws IOException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException {
        Cipher dcipher;
        dcipher = Cipher.getInstance("RSA");
        dcipher.init(Cipher.DECRYPT_MODE, priv);
        byte[] dec = new sun.misc.BASE64Decoder().decodeBuffer(str);
        byte[] utf8 = dcipher.doFinal(dec);
        return new String(utf8, "UTF8");
    }
    public static byte[] controlmsg(String text, SecretKey key) {
        byte[] cipherText = null;
        try {
            final Cipher cipher = Cipher.getInstance("Blowfish");
            cipher.init(Cipher.ENCRYPT_MODE, key);
            cipherText = cipher.doFinal(text.getBytes());
        } catch (Exception e) {
            e.printStackTrace();
        }
        return cipherText;
    }

    public static String byte2Hex(byte b[]) {
        java.lang.String hs = "";
        java.lang.String stmp = "";
        for (int n = 0; n < b.length; n++) {
            stmp = java.lang.Integer.toHexString(b[n] & 0xff);
            if (stmp.length() == 1)
                hs = hs + "0" + stmp;
            else
                hs = hs + stmp;
        }
        return hs.toLowerCase();
    }

    public static byte[] hex2Byte(String str) {
        int len = str.length();
        if (len % 2 != 0) return null;
        byte r[] = new byte[len / 2];
        int k = 0;
        for (int i = 0; i < str.length() - 1; i += 2) {
            r[k] = hex2Byte(str.charAt(i), str.charAt(i + 1));
            k++;
        }
        return r;
    }

    public static byte hex2Byte(char a1, char a2) {
        int k;
        if (a1 >= '0' && a1 <= '9') k = a1 - 48;
        else if (a1 >= 'a' && a1 <= 'f') k = (a1 - 97) + 10;
        else if (a1 >= 'A' && a1 <= 'F') k = (a1 - 65) + 10;
        else k = 0;
        k <<= 4;
        if (a2 >= '0' && a2 <= '9') k += a2 - 48;
        else if (a2 >= 'a' && a2 <= 'f') k += (a2 - 97) + 10;
        else if (a2 >= 'A' && a2 <= 'F') k += (a2 - 65) + 10;
        else k += 0;
        return (byte) (k & 0xff);
    }

}
