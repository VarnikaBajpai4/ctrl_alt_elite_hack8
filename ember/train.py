

from ember.features import PEFeatureExtractor
import numpy as np
import hashlib

# Setup
extractor = PEFeatureExtractor(feature_version=2)

X_new = []
y_new = []

benign_samples = [

    ("./data/docker/data/data/benign1.exe", 0.0),
    ("./data/docker/data/data/benign2.exe", 0.0),
    ("./data/docker/data/data/benign3.exe", 0.0),
    ("./data/docker/data/data/benign4.exe", 0.0),
    ("./data/docker/data/data/benign5.exe", 0.0),
    ("./data/docker/data/data/benign6.exe", 0.0),
    ("./data/docker/data/data/benign7.exe", 0.0),
    ("./data/docker/data/data/benign8.exe", 0.0),
    ("./data/docker/data/data/benign9.exe", 0.0),
    ("./data/docker/data/data/benign10.exe", 0.0),
    ("./data/docker/data/data/benign11.exe", 0.0),
    ("./data/docker/data/data/benign12.exe", 0.0),
    ("./data/docker/data/data/benign13.exe", 0.0),
    ("./data/docker/data/data/benign14.exe", 0.0),
    ("./data/docker/data/data/benign15.exe", 0.0),
    ("./data/docker/data/data/benign16.exe", 0.0),
    ("./data/docker/data/data/benign17.exe", 0.0),
    ("./data/docker/data/data/benign18.exe", 0.0),
    ("./data/docker/data/data/benign19.exe", 0.0),
    ("./data/docker/data/data/benign20.exe", 0.0),
    ("./data/docker/data/data/benign21.exe", 0.0),
    ("./data/docker/data/data/benign22.exe", 0.0),
    # ("../data/docker/data/data/benign23.exe", 0.0),
    # ("../data/docker/data/data/benign24.exe", 0.0),
    # ("../data/docker/data/data/benign25.exe", 0.0),
    # ("../data/docker/data/data/benign26.exe", 0.0),
    # ("../data/docker/data/data/benign27.exe", 0.0),
    # ("../data/docker/data/data/benign28.exe", 0.0),
    # ("../data/docker/data/data/benign29.exe", 0.0),
    # ("../data/docker/data/data/benign30.exe", 0.0),
    # ("../data/docker/data/data/benign31.exe", 0.0),
    # ("../data/docker/data/data/benign32.exe", 0.0),
    # ("../data/docker/data/data/benign33.exe", 0.0),
    # ("../data/docker/data/data/benign34.exe", 0.0),
    # ("../data/docker/data/data/benign35.exe", 0.0),
    # ("../data/docker/data/data/benign36.exe", 0.0),
    # ("../data/docker/data/data/benign37.exe", 0.0),
    # ("../data/docker/data/data/benign38.exe", 0.0),
    # ("../data/docker/data/data/benign39.exe", 0.0),
    # ("../data/docker/data/data/benign40.exe", 0.0),
    # ("../data/docker/data/data/benign41.exe", 0.0),
    # ("../data/docker/data/data/benign42.exe", 0.0),
    # ("../data/docker/data/data/benign43.exe", 0.0),
    # ("../data/docker/data/data/benign44.exe", 0.0),
    # ("../data/docker/data/data/benign45.exe", 0.0),
    # ("../data/docker/data/data/benign46.exe", 0.0),
    # ("../data/docker/data/data/benign47.exe", 0.0),
    # ("../data/docker/data/data/benign48.exe", 0.0),
    # ("../data/docker/data/data/benign49.exe", 0.0),
    # ("../data/docker/data/data/benign50.exe", 0.0),
    # ("../data/docker/data/data/benign51.exe", 0.0),
    # ("../data/docker/data/data/benign52.exe", 0.0),
    # ("../data/docker/data/data/benign53.exe", 0.0),
    # ("../data/docker/data/data/benign54.exe", 0.0),
    # ("../data/docker/data/data/benign55.exe", 0.0),
    # ("../data/docker/data/data/benign56.exe", 0.0),
    # ("../data/docker/data/data/benign57.exe", 0.0),
    # ("../data/docker/data/data/benign58.exe", 0.0),
    # ("../data/docker/data/data/benign59.exe", 0.0),
    # ("../data/docker/data/data/benign60.exe", 0.0),
    # ("../data/docker/data/data/benign61.exe", 0.0),
    # ("../data/docker/data/data/benign62.exe", 0.0),
    # ("../data/docker/data/data/benign63.exe", 0.0),
    # ("../data/docker/data/data/benign64.exe", 0.0),
    # ("../data/docker/data/data/benign65.exe", 0.0),
    # ("../data/docker/data/data/benign66.exe", 0.0),
    # ("../data/docker/data/data/benign67.exe", 0.0),
    # ("../data/docker/data/data/benign68.exe", 0.0),
    # ("../data/docker/data/data/benign69.exe", 0.0),
    # ("../data/docker/data/data/benign70.exe", 0.0),
    # ("../data/docker/data/data/benign71.exe", 0.0),
    # ("../data/docker/data/data/benign72.exe", 0.0),
    # ("../data/docker/data/data/benign73.exe", 0.0),
    # ("../data/docker/data/data/benign74.exe", 0.0),
    # ("../data/docker/data/data/benign75.exe", 0.0),
    # ("../data/docker/data/data/benign76.exe", 0.0),
    # ("../data/docker/data/data/benign77.exe", 0.0),
    # ("../data/docker/data/data/benign78.exe", 0.0),
    # ("../data/docker/data/data/benign79.exe", 0.0),
    # ("../data/docker/data/data/benign80.exe", 0.0),
    # ("../data/docker/data/data/benign81.exe", 0.0),
    # ("../data/docker/data/data/benign82.exe", 0.0),
    # ("../data/docker/data/data/benign83.exe", 0.0),
    # ("../data/docker/data/data/benign84.exe", 0.0),
    # ("../data/docker/data/data/benign85.exe", 0.0),
    # ("../data/docker/data/data/benign86.exe", 0.0),
    # ("../data/docker/data/data/benign87.exe", 0.0),
    # ("../data/docker/data/data/benign88.exe", 0.0),
    # ("../data/docker/data/data/benign89.exe", 0.0),
    # ("../data/docker/data/data/benign90.exe", 0.0),
    # ("../data/docker/data/data/benign91.exe", 0.0),
    # ("../data/docker/data/data/benign92.exe", 0.0),
    # ("../data/docker/data/data/benign93.exe", 0.0),
    # ("../data/docker/data/data/benign94.exe", 0.0),
    # ("../data/docker/data/data/benign95.exe", 0.0),
    # ("../data/docker/data/data/benign96.exe", 0.0),
    # ("../data/docker/data/data/benign97.exe", 0.0),
    # ("../data/docker/data/data/benign98.exe", 0.0),
    # ("../data/docker/data/data/benign99.exe", 0.0),
]

# Sample files
malware_samples = [ 
    #("../data/docker/data/data/benign0.exe", 0.0),
    

    # # test101 to test300
    ("./data/docker/data/data/test1.exe", 1.0),
    ("./data/docker/data/data/test2.exe", 1.0),
    ("./data/docker/data/data/test3.exe", 1.0),
    ("./data/docker/data/data/test4.exe", 1.0),
    ("./data/docker/data/data/test5.exe", 1.0),
    ("./data/docker/data/data/test6.exe", 1.0),
    ("./data/docker/data/data/test7.exe", 1.0),
    ("./data/docker/data/data/test8.exe", 1.0),
    ("./data/docker/data/data/test9.exe", 1.0),
    ("./data/docker/data/data/test10.exe", 1.0),
    ("./data/docker/data/data/test11.exe", 1.0),
    ("./data/docker/data/data/test12.exe", 1.0),
    ("./data/docker/data/data/test13.exe", 1.0),
    ("./data/docker/data/data/test14.exe", 1.0),
    ("./data/docker/data/data/test15.exe", 1.0),
    ("./data/docker/data/data/test16.exe", 1.0),
    ("./data/docker/data/data/test17.exe", 1.0),
    ("./data/docker/data/data/test18.exe", 1.0),
    ("./data/docker/data/data/test19.exe", 1.0),
    ("./data/docker/data/data/test20.exe", 1.0),
    ("./data/docker/data/data/test21.exe", 1.0),
    ("./data/docker/data/data/test22.exe", 1.0),
    # ("../data/docker/data/data/test23.exe", 1.0),
    # ("../data/docker/data/data/test24.exe", 1.0),
    # ("../data/docker/data/data/test25.exe", 1.0),
    # ("../data/docker/data/data/test26.exe", 1.0),
    # ("../data/docker/data/data/test27.exe", 1.0),
    # ("../data/docker/data/data/test28.exe", 1.0),
    # ("../data/docker/data/data/test29.exe", 1.0),
    # ("../data/docker/data/data/test30.exe", 1.0),
    # ("../data/docker/data/data/test31.exe", 1.0),
    # ("../data/docker/data/data/test32.exe", 1.0),
    # ("../data/docker/data/data/test133.exe", 1.0),
    # ("../data/docker/data/data/test134.exe", 1.0),
    # ("../data/docker/data/data/test135.exe", 1.0),
    # ("../data/docker/data/data/test136.exe", 1.0),
    # ("../data/docker/data/data/test137.exe", 1.0),
    # ("../data/docker/data/data/test138.exe", 1.0),
    # ("../data/docker/data/data/test139.exe", 1.0),
    # ("../data/docker/data/data/test140.exe", 1.0),
    # ("../data/docker/data/data/test141.exe", 1.0),
    # ("../data/docker/data/data/test142.exe", 1.0),
    # ("../data/docker/data/data/test143.exe", 1.0),
    # ("../data/docker/data/data/test144.exe", 1.0),
    # ("../data/docker/data/data/test145.exe", 1.0),
    # ("../data/docker/data/data/test146.exe", 1.0),
    # ("../data/docker/data/data/test147.exe", 1.0),
    # ("../data/docker/data/data/test148.exe", 1.0),
    # ("../data/docker/data/data/test149.exe", 1.0),
    # ("../data/docker/data/data/test150.exe", 1.0),
    # ("../data/docker/data/data/test151.exe", 1.0),
    # ("../data/docker/data/data/test152.exe", 1.0),
    # ("../data/docker/data/data/test153.exe", 1.0),
    # ("../data/docker/data/data/test154.exe", 1.0),
    # ("../data/docker/data/data/test155.exe", 1.0),
    # ("../data/docker/data/data/test156.exe", 1.0),
    # ("../data/docker/data/data/test157.exe", 1.0),
    # ("../data/docker/data/data/test158.exe", 1.0),
    # ("../data/docker/data/data/test159.exe", 1.0),
    # ("../data/docker/data/data/test160.exe", 1.0),
    # ("../data/docker/data/data/test161.exe", 1.0),
    # ("../data/docker/data/data/test162.exe", 1.0),
    # ("../data/docker/data/data/test163.exe", 1.0),
    # ("../data/docker/data/data/test164.exe", 1.0),
    # ("../data/docker/data/data/test165.exe", 1.0),
    # ("../data/docker/data/data/test166.exe", 1.0),
    # ("../data/docker/data/data/test167.exe", 1.0),
    # ("../data/docker/data/data/test168.exe", 1.0),
    # ("../data/docker/data/data/test169.exe", 1.0),
    # ("../data/docker/data/data/test170.exe", 1.0),
    # ("../data/docker/data/data/test171.exe", 1.0),
    # ("../data/docker/data/data/test172.exe", 1.0),
    # ("../data/docker/data/data/test173.exe", 1.0),
    # ("../data/docker/data/data/test174.exe", 1.0),
    # ("../data/docker/data/data/test175.exe", 1.0),
    # ("../data/docker/data/data/test176.exe", 1.0),
    # ("../data/docker/data/data/test177.exe", 1.0),
    # ("../data/docker/data/data/test178.exe", 1.0),
    # ("../data/docker/data/data/test179.exe", 1.0),
    # ("../data/docker/data/data/test180.exe", 1.0),
    # ("../data/docker/data/data/test181.exe", 1.0),
    # ("../data/docker/data/data/test182.exe", 1.0),
    # ("../data/docker/data/data/test183.exe", 1.0),
    # ("../data/docker/data/data/test184.exe", 1.0),
    # ("../data/docker/data/data/test185.exe", 1.0),
    # ("../data/docker/data/data/test186.exe", 1.0),
    # ("../data/docker/data/data/test187.exe", 1.0),
    # ("../data/docker/data/data/test188.exe", 1.0),
    # ("../data/docker/data/data/test189.exe", 1.0),
    # ("../data/docker/data/data/test190.exe", 1.0),
    # ("../data/docker/data/data/test191.exe", 1.0),
    # ("../data/docker/data/data/test192.exe", 1.0),
    # ("../data/docker/data/data/test193.exe", 1.0),
    # ("../data/docker/data/data/test194.exe", 1.0),
    # ("../data/docker/data/data/test195.exe", 1.0),
    # ("../data/docker/data/data/test196.exe", 1.0),
    # ("../data/docker/data/data/test197.exe", 1.0),
    # ("../data/docker/data/data/test198.exe", 1.0),
    # ("../data/docker/data/data/test199.exe", 1.0),
    # ("../data/docker/data/data/test200.exe", 1.0),
]
samples = benign_samples*15 + malware_samples * 7
# Extract features
for filepath, label in samples:
    with open(filepath, "rb") as f:
        bytez = f.read()
    try:
        feature_vector = extractor.feature_vector(bytez)
        X_new.append(feature_vector)
        y_new.append(label)
    except Exception as e:
        print(f"Error processing {filepath}: {e}")

X_new = np.array(X_new, dtype=np.float32)
y_new = np.array(y_new, dtype=np.float32)
import lightgbm as lgb

# Load the pre-trained EMBER model
booster = lgb.Booster(model_file="./models/ember_model_final.txt")

# Create LightGBM Dataset from new samples
new_data = lgb.Dataset(X_new, y_new)

# Continue training
booster = lgb.train(
    params={"objective": "binary"},
    train_set=new_data,
    num_boost_round=50,                # You can tune this*
    init_model=booster,
    keep_training_booster=True
)

# Save updated model
booster.save_model("./models/ember_model_final3.txt")
print("✅ Model fine-tuned and saved as ember_model_final.txt")