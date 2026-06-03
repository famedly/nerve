#!/usr/bin/env bash
# Smoke test for datapoint server: stride=4, two interleaved clients.
set -u
FILE=/tmp/datapoint_test.bin
rm -f "$FILE"

./target/release/datapoint serve 4 127.0.0.1:19000 "$FILE" &
SERVER=$!
sleep 0.2

printf '\x04AAAABBBB' | nc -q1 127.0.0.1 19000 &
printf '\x04CCCCDDDD' | nc -q1 127.0.0.1 19000 &
wait %2 %3
sleep 0.2

kill "$SERVER" 2>/dev/null
wait 2>/dev/null

echo "--- cat output (hex) ---"
./target/release/datapoint cat "$FILE" | xxd
echo "--- size ---"
stat -c%s "$FILE"

echo "--- stride mismatch test (expect connection drop, file size unchanged) ---"
./target/release/datapoint serve 4 127.0.0.1:19001 "$FILE.mismatch" &
SERVER=$!
sleep 0.2
rm -f "$FILE.mismatch"
# wrong stride 8, then some bytes that must NOT be written
printf '\x08XXXXXXXX' | nc -q1 127.0.0.1 19001
sleep 0.2
kill "$SERVER" 2>/dev/null
wait 2>/dev/null
if [ -f "$FILE.mismatch" ]; then
  echo "mismatch file size: $(stat -c%s "$FILE.mismatch")"
else
  echo "mismatch file not created (ok)"
fi
