// Fixture con pattern volutamente insicuri: NON usare come esempio.
package main

func handler() {
	// sbd-expect-next: P-TLS-01
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	// sbd-expect-next: P-EXEC-06
	out, _ := exec.Command("sh", "-c", "ping "+host).Output()
	// sbd-expect-next: P-CRYPTO-04
	token := fmt.Sprint(rand.Int63())
	// sbd-expect-next: P-SQLI-01
	db.Query(fmt.Sprintf("SELECT name FROM users WHERE email = '%s'", email))
	// sbd-expect-next: P-CRYPTO-01
	h := md5.Sum(data)
}
