#!/usr/bin/env bash

# EID cible (modifie si besoin)
TARGET_EID="ipn:10.42"

# Fonction d'envoi
send() {
  label="$1"
  file="$2"
  echo "[*] Sending payload: $label"
  bpsource "$TARGET_EID" < "$file"
}

# Répertoire temporaire
TMPDIR=$(mktemp -d)
trap "rm -rf $TMPDIR" EXIT

# 1) Texte ASCII simple
echo "Hello world" > "$TMPDIR/ascii.txt"
send "ascii" "$TMPDIR/ascii.txt"

# 2) Texte UTF-8 multibyte
echo "こんにちは世界" > "$TMPDIR/utf8.txt"
send "utf8" "$TMPDIR/utf8.txt"

# 3) JSON
echo '{"key": "value"}' > "$TMPDIR/json.txt"
send "json" "$TMPDIR/json.txt"

# 4) Binaire incrémental (0x00 à 0xFF)
for i in $(seq 0 255); do
  printf "\\x$(printf %02x $i)"
done > "$TMPDIR/incremental.bin"
send "incremental" "$TMPDIR/incremental.bin"

# 5) Binaire uniforme (0xAA)
head -c 1024 < /dev/zero | tr '\0' '\xAA' > "$TMPDIR/uniform.bin"
send "uniform" "$TMPDIR/uniform.bin"

# 6) Données aléatoires (4 Ko)
head -c 4096 < /dev/urandom > "$TMPDIR/random.bin"
send "random" "$TMPDIR/random.bin"

# 7) Gros fichier (1 Mo)
head -c $((1 * 1024 * 1024)) < /dev/zero > "$TMPDIR/big.bin"
send "big" "$TMPDIR/big.bin"

echo "[+] All bundles sent successfully."
