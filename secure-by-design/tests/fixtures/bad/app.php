<?php
// Fixture con pattern volutamente insicuri: NON usare come esempio.
// sbd-expect-next: P-DESER-05
$data = unserialize($_COOKIE['prefs']);
// sbd-expect-next: P-EXEC-01
eval($_POST['code']);
