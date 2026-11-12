#!/usr/bin/env bash
# Finale P5: rebuild every text asset and the deck from claims_used_for_finale.json, export the PDF, rasterise each page.
#   bash finale_package/src/build_all.sh MEDIA_DIR        (MEDIA_DIR holds screens/, term/, recordings/; output pages go to MEDIA_DIR/deck/)
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; PKG="$(dirname "$HERE")"; REPO="$(dirname "$PKG")"
MEDIA="$1"
PY="${MEDIA_PY:-python3}"
"$REPO/aegislab/.venv/bin/python" "$REPO/aegislab/evaluation/check_finale_presentation.py" --write-claims
"$PY" "$HERE/render_docs.py" "$PKG/claims_used_for_finale.json" --all
"$PY" "$HERE/build_finale_deck.py" "$PKG/claims_used_for_finale.json" "$MEDIA" "$PKG/Tech_Mavericks_AegisLab_Finale.pptx"
LO="$(mktemp -d)"; trap 'rm -rf "$LO"' EXIT
( cd "$PKG" && timeout 300 soffice -env:UserInstallation="file://$LO" --headless --convert-to pdf Tech_Mavericks_AegisLab_Finale.pptx >/dev/null 2>&1 )
mkdir -p "$MEDIA/deck"; rm -f "$MEDIA/deck"/page-*.png
pdftoppm -r 96 -png "$PKG/Tech_Mavericks_AegisLab_Finale.pdf" "$MEDIA/deck/page"
ls "$MEDIA/deck" | wc -l
# one-page handout: HANDOUT.md -> HTML -> PDF (LibreOffice writer_web_pdf_Export)
python3 "$HERE/handout_pdf.py" "$PKG/HANDOUT.md" "$LO/AegisLab_Finale_Handout.html"
( cd "$LO" && timeout 120 soffice -env:UserInstallation="file://$LO/u2" --headless --convert-to pdf:writer_web_pdf_Export AegisLab_Finale_Handout.html >/dev/null 2>&1 )
cp "$LO/AegisLab_Finale_Handout.pdf" "$PKG/AegisLab_Finale_Handout.pdf"
pdfinfo "$PKG/AegisLab_Finale_Handout.pdf" | grep Pages
