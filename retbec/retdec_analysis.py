#!/usr/bin/env python3
import os
import json
import sys

def run_extractor_and_save(malware_dir):
    """
    Import and run retbec/extract_features.py on malware_dir,
    then write features.json into that folder.
    """
    # ensure retbec folder is on PYTHONPATH
    script_dir = os.path.dirname(os.path.realpath(__file__))
    retbec_dir = os.path.join(script_dir)
    sys.path.insert(0, retbec_dir)

    try:
        from extract_features import extract_features as extf
    except ImportError as e:
        print(f"[!] Cannot import extract_features: {e}", file=sys.stderr)
        return False, {}

    feats = extf(malware_dir)
    out_path = os.path.join(malware_dir, "features.json")
    try:
        with open(out_path, "w") as f:
            json.dump(feats, f, indent=4)
        return True, feats
    except Exception as e:
        print(f"[!] Failed to write features.json: {e}", file=sys.stderr)
        return False, {}

def check_retbec_features(malware_dir):
    features_path = os.path.join(malware_dir, "features.json")
    if os.path.isfile(features_path):
        with open(features_path, "r") as f:
            feats = json.load(f)
        return True, feats
    # else, run extractor
    return run_extractor_and_save(malware_dir)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python retbec_check.py <path-to-retdec-output-dir>", file=sys.stderr)
        sys.exit(1)

    folder = sys.argv[1]
    success, features = check_retbec_features(folder)
    print(json.dumps({
        "retbec_success": success,
        "retbec_features": features if success else None
    }, indent=4))
