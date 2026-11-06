#!/bin/bash
# Kiểm thử klock. Cần: $KL đã build, `tle` thật trong PATH.
# STUB=1 : chạy với tle giả (bỏ qua các bước thử khóa thời gian).
# DELAY=90 : số giây khóa (mặc định 90).
cd "$(dirname "$0")/.."; KL=./target/release/klock; [ -x "$KL" ] || cargo build --release -q
W=$(mktemp -d); S="correct horse battery staple"; MSG="How are you?"; DELAY=${DELAY:-90}
ok=0; bad=0
chk() { if [ "$2" = "$3" ]; then echo "PASS  $1"; ok=$((ok+1)); else echo "FAIL  $1 (nhận: '$2')"; bad=$((bad+1)); fi; }

T=$(date -u -d "+${DELAY} seconds" +%d%m%Y%H%M%S)          # DDMMYYYYHHMMSS (UTC)
$KL enc "$S" "$T" "$MSG" > $W/out.txt 2>$W/err.txt
CODE=$(head -1 $W/out.txt); tail -n +2 $W/out.txt > $W/blob.txt
echo "chuỗi số: $CODE  (mở lúc $T UTC)"
chk "chuỗi số kết thúc bằng thời điểm" "${CODE: -14}" "$T"

if [ -z "$STUB" ]; then
  r=$($KL dec "$S" "$CODE" < $W/blob.txt 2>&1 | head -c 200)
  case "$r" in *"How are you"*) chk "trước giờ KHÔNG được mở" "mở được" "không mở";; *) chk "trước giờ KHÔNG được mở" "không mở" "không mở";; esac
  echo "...chờ ${DELAY}s (+5s dự phòng) cho vòng drand"; sleep $((DELAY+5))
fi

chk "đúng S, đủ giờ -> mở được" "$($KL dec "$S" "$CODE" < $W/blob.txt 2>/dev/null)" "$MSG"
r=$($KL dec "Correct horse battery staple" "$CODE" < $W/blob.txt 2>&1 | grep -c "sai bí mật"); chk "sai S (viết hoa) bị từ chối" "$r" "1"
EARLY="${CODE%??????????????}01012000000000"
r=$($KL dec "$S" "$EARLY" < $W/blob.txt 2>&1 | grep -c "sai bí mật"); chk "sửa ngày trong chuỗi số bị từ chối" "$r" "1"
X0="${CODE%??????????????}"; r=$($KL dec "$S" "$((10#$X0 + 1))${CODE: -14}" < $W/blob.txt 2>&1 | grep -c "sai bí mật"); chk "sửa x0 bị từ chối" "$r" "1"
echo "kết quả: $ok đạt, $bad lỗi"; [ $bad -eq 0 ]
