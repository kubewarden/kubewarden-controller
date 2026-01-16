#!/bin/bash
set -euo pipefail

CHART_DIR=$1
CHARTS_DIRS=$(find "$CHART_DIR" -type d -exec test -e '{}'/values.yaml \; -print | grep -v kubewarden-crds)
IMAGELIST_FILENAME=imagelist.txt
TMP_IMAGE_FILE=/tmp/$IMAGELIST_FILENAME

find "$CHART_DIR" -type f -name $IMAGELIST_FILENAME -delete
if [ -e $IMAGELIST_FILENAME ]; then
       rm $IMAGELIST_FILENAME
fi

for chart in $CHARTS_DIRS; do
	# the set CLI flag is used only by the controller chart. But to
	# simplify the script, it will be passed for all the chart. It will be
	# ignore for the other chart anyway
	helm template --values "$chart"/values.yaml --set auditScanner.policyReporter=true "$chart"/ | yq -r "..|.image?" | grep -v "null"  > $TMP_IMAGE_FILE
	sed --in-place '/---/d' $TMP_IMAGE_FILE
	mv $TMP_IMAGE_FILE "$chart"/$IMAGELIST_FILENAME 
done

# Delete the empty imagelist.txt files.
find "$CHART_DIR" -type f -name $IMAGELIST_FILENAME -empty -delete
find "$CHART_DIR" -type f -name $IMAGELIST_FILENAME -print0 | xargs --null cat > $TMP_IMAGE_FILE
mv $TMP_IMAGE_FILE $IMAGELIST_FILENAME

find "$CHART_DIR" -type f -name $IMAGELIST_FILENAME -exec sort -u -o \{\} \{\} \;
sort -u -o $IMAGELIST_FILENAME $IMAGELIST_FILENAME
