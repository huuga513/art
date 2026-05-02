#!/bin/bash

BASE_DIR="/ssd2/wyz/app_oats"
OLD_VER="15.0.0_r3"
NEW_VER="15.0.0_r5"
OATCHECK_DIR="/ssd2/wyz/AOSP/art/oatcheck"

for app in "$BASE_DIR/$NEW_VER"/*/; do
    app_name=$(basename "$app")
    echo "===== Processing $app_name ====="

    fixed_oat="$BASE_DIR/$NEW_VER/$app_name/oat/base.odex"
    original_oat="$BASE_DIR/$OLD_VER/$app_name/oat/base.odex"
    apk="$BASE_DIR/$OLD_VER/$app_name/base.apk"

    diff_log="$OATCHECK_DIR/diff_${app_name}.log"
    result_log="$OATCHECK_DIR/result_${app_name}.log"

    echo "Step 1: Compare code..."
    python3 "$OATCHECK_DIR/test_fix_validation_host.py" \
        --fixed-oat="$fixed_oat" \
        --original-oat="$original_oat" \
        --compare-code --max-diffs=1000 > "$diff_log" 2>&1

    echo "Step 2: Run oatcheck..."
    python3 "$OATCHECK_DIR/oatcheck_host.py" \
        --apk="$apk" \
        --oat="$original_oat" \
        --origin-bcp-prefix=/ssd2/wyz/bcp_classes/15r3 \
        --updated-bcp-prefix=/ssd2/wyz/bcp_classes/15r5 > "$result_log" 2>&1

    echo "Step 3: Find missing methods..."
    python3 "$OATCHECK_DIR/find_missing_methods.py" "$diff_log" "$result_log"

    echo "===== Done $app_name ====="
    echo ""
done
