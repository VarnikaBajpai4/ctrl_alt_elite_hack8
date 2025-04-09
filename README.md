```markdown
# Installation Commands

```bash
pip install numpy pandas scikit-learn matplotlib seaborn tensorflow lightgbm
```

Above are all the installation commands executed up until now.

# Project Setup

To set up this project, run:

```bash
python -m venv venv
venv/Scripts/activate
pip install -r requirements.txt
```

### Testing the Setup

After installing the requirements, you can test it by running the files `predict.py` and `sample_usage.py` as given below.

### Training Command

```bash
python train.py --data_path ./ --model cnn --epochs 5
```

### Running Commands

```bash
python predict.py --data_path ./ --model cnn --visualize
python sample_usage.py
```

# Required Data Files

In order to actually run the training, you'll need the following files:

- `X_test.dat`
- `X_train.dat`
- `y_test.dat`
- `y_train.dat`

These files should be placed inside the root directory of your folder where your Python files and `requirements.txt` are located. You'll have to download them from the drive links provided below:

- [X_test.dat](https://drive.google.com/file/d/1fUQQs18wPZQjnRqAayxZsPqFXb62gB4e/view?usp=sharing)
- [X_train.dat](https://drive.google.com/file/d/1lOJPbdiaYdNjEvkyoo66sIiKayvGn-WQ/view?usp=sharing)
- [y_test.dat](https://drive.google.com/file/d/1fpJ_2MCzuLP1i4up5djFtT72AJBKeV74/view?usp=sharing)
- [y_train.dat](https://drive.google.com/file/d/1In1MXtJ1XhppFt-EB3y_tX7YMhgL3jbv/view?usp=sharing)

### Alternative Download Source

Alternatively, these files can also be downloaded from:

[Kaggle Dataset - Ember for Static Malware Analysis](https://www.kaggle.com/datasets/trinhvanquynh/ember-for-static-malware-analysis/code)
```