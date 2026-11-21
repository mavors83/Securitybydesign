/* Fixture con pattern volutamente insicuri: NON usare come esempio. */
void f(char *src, char *cmd) {
  char buf[16];
  /* sbd-expect-next: P-MEM-01 */
  strcpy(buf, src);
  /* sbd-expect-next: P-EXEC-07 */
  system(cmd);
}
