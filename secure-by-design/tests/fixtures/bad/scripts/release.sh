#!/bin/sh
# Fixture con pattern volutamente insicuri: NON usare come esempio.
# sbd-expect-next: P-SHELL-03
git commit -am "release" --no-verify
# sbd-expect-next: P-TLS-02
git -c http.sslVerify=false clone https://git.example.com/repo.git
