import os
import re

import numpy as np
import pytest

import ml_detector
from ml_detector import ModelTrainer, SyntheticDataGenerator


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def test_synthetic_generator_shapes():
    X, y = SyntheticDataGenerator.generate_dataset(n_benign=200, n_attack=50)
    assert X.shape == (250, 12)
    assert y.shape == (250,)
    assert set(np.unique(y)) == {0, 1}
    assert X.dtype == float


def test_synthetic_generator_is_seeded():
    X1, y1 = SyntheticDataGenerator.generate_dataset(n_benign=100, n_attack=20)
    X2, y2 = SyntheticDataGenerator.generate_dataset(n_benign=100, n_attack=20)
    assert np.array_equal(y1, y2)


def test_isolation_forest_trains_and_predicts():
    X, y = SyntheticDataGenerator.generate_dataset(n_benign=400, n_attack=100)
    trainer = ModelTrainer(model_type="isolation_forest")
    trainer.train(X, y)
    preds, confs = trainer.predict(X)
    assert len(preds) == len(X)
    assert len(confs) == len(X)
    assert set(np.unique(preds)).issubset({0, 1})


def test_model_accuracy_above_floor():
    X, y = SyntheticDataGenerator.generate_dataset(n_benign=800, n_attack=200)
    trainer = ModelTrainer(model_type="random_forest")
    trainer.train(X, y)
    preds, _ = trainer.predict(X)
    accuracy = (preds == y).mean()
    assert accuracy >= 0.80


def test_feature_columns_count():
    assert len(ModelTrainer.FEATURE_COLUMNS) == 12