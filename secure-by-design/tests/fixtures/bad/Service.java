// Fixture con pattern volutamente insicuri: NON usare come esempio.
public class Service {
  void run(String file, String id, InputStream in) throws Exception {
    // sbd-expect-next: P-CRYPTO-01
    MessageDigest md = MessageDigest.getInstance("MD5");
    // sbd-expect-next: P-CRYPTO-02
    Cipher c = Cipher.getInstance("AES/ECB/PKCS5Padding");
    // sbd-expect-next: P-CRYPTO-03
    Cipher d = Cipher.getInstance("DESede/CBC/PKCS5Padding");
    // sbd-expect-next: P-CRYPTO-04
    String otp = String.valueOf(new Random().nextInt(999999));
    // sbd-expect-next: P-TLS-01
    HttpClients.custom().setSSLHostnameVerifier(NoopHostnameVerifier.INSTANCE);
    // sbd-expect-next: P-EXEC-05
    Runtime.getRuntime().exec("sh -c " + file);
    // sbd-expect-next: P-DESER-03
    Object o = new ObjectInputStream(in).readObject();
    // sbd-expect-next: P-SQLI-01
    stmt.executeQuery("SELECT * FROM accounts WHERE id = '" + id + "'");
    // sbd-expect-next: P-SQLI-02
    Statement stmt = conn.createStatement();
    // sbd-expect-next: P-WEB-02
    http.csrf(csrf -> csrf.disable());
    // sbd-expect-next: P-XXE-01
    xif.setProperty(XMLInputFactory.SUPPORT_DTD, true);
    // sbd-expect-next: P-MISC-02
    getSharedPreferences("prefs", MODE_WORLD_READABLE);
  }

  // sbd-expect-next: P-WEB-01
  @CrossOrigin(origins = "*")
  void endpoint() {}
}
