from tensorflow.keras.models import load_model
#import Tokenizer
from tensorflow.keras.preprocessing.text import Tokenizer
from tensorflow.keras.preprocessing.sequence import pad_sequences
from tensorflow.keras.preprocessing.image import ImageDataGenerator
from sklearn.preprocessing import StandardScaler
from sklearn.decomposition import PCA
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score
from sklearn.model_selection import train_test_split

import numpy as np
import pandas as pd
import os
import logging
import importlib.util
import sys
import json
import pickle
import pefile
import joblib

from lib.cuckoo.common.abstracts import Processing
from lib.cuckoo.common.objects import File
from lib.cuckoo.common.exceptions import CuckooProcessingError
from lib.cuckoo.common.utils import *

class MLDynamic(Processing):
    """Machine Learning Dynamic Analysis Module."""
    key = "ml_detection"
    order = 9999

    def get_apilist(self):
        """Get the API list for the dynamic analysis module."""
        apilist = []
        for process in self.results["behavior"]["processes"]:
            if process["process_name"] == "lsass.exe":
                # Skip lsass.exe process
                continue
            for api in process["calls"]:
                apilist.append(api["api"])
        return apilist
    
    def bilstm(self):
        """Run the bilstm model for dynamic analysis."""

        # # Check if the required libraries are installed
        # if importlib.util.find_spec("lief") is None:
        #     raise ImportError("lief module not found. Please install lief library to use this module.")
        # if importlib.util.find_spec("numpy") is None:
        #     raise ImportError("numpy module not found. Please install numpy library to use this module.")
        # if importlib.util.find_spec("sklearn") is None:
        #     raise ImportError("sklearn module not found. Please install sklearn library to use this module.")

        # # Load the model

        model = load_model(self.options["model_path"])
        
        # Load the tokenizer
        with open(self.options["tokenizer_path"], 'rb') as handle:
            tokenizer = pickle.load(handle)

        apilist = self.get_apilist()
        # Check if the API list is empty

        if not apilist:
            log.info("No API calls found in the analysis results.")
            return {
                    "class": "unknown",
                    "prediction": "unknown",
                }
        # Preprocess the API list
        # Tokenize the API list
        sequences = tokenizer.texts_to_sequences([apilist])
        # Pad the sequences
        padded_sequences = pad_sequences(sequences, maxlen=self.options["max_seq_len"])
        # Convert to numpy array
        padded_sequences = np.array(padded_sequences)
        prediction = model.predict(padded_sequences)
        
        # Get the predicted class
        log.info(f"Prediction: {prediction}")
        if prediction[0][0] > 0.5:
            prediction_class = "malicious"
        else:
            prediction_class = "clean"
        
        result = {
                "class": prediction_class,
                "prediction": str(prediction[0][0]),
            }

        # Save the result to the results dictionary
        return result
    def extract_features(self, file_path):
        pe = pefile.PE(file_path)
        """Extract features from the PE file."""
        f1 = pe.OPTIONAL_HEADER.ImageBase
        f2 = pe.OPTIONAL_HEADER.SectionAlignment
        f3 = pe.OPTIONAL_HEADER.FileAlignment
        f4 = pe.OPTIONAL_HEADER.MajorSubsystemVersion
        f5 = pe.OPTIONAL_HEADER.MajorImageVersion
        f6 = pe.OPTIONAL_HEADER.MajorOperatingSystemVersion
        f7 = pe.OPTIONAL_HEADER.Subsystem
        f8 = pe.OPTIONAL_HEADER.DllCharacteristics
        f9 = pe.OPTIONAL_HEADER.SizeOfStackReserve
        f10 = pe.OPTIONAL_HEADER.SizeOfStackCommit
        f11 = pe.OPTIONAL_HEADER.SizeOfHeapCommit
        f12 = pe.OPTIONAL_HEADER.SizeOfHeaders
        f13 = pe.OPTIONAL_HEADER.DATA_DIRECTORY[2].Size
        f14 = pe.OPTIONAL_HEADER.BaseOfCode
        f15 = pe.OPTIONAL_HEADER.MinorOperatingSystemVersion
        return np.array([
            f1, f2, f3, f4, f5, f6, f7, f8,
            f9, f10, f11, f12, f13, f14, f15
        ]).reshape(1, -1)
    
    def static_random_forest(self):
        """Run the static random forest model for dynamic analysis."""
        # Check whether the target file is a PE file
        file = File(self.file_path)
        ftype = file.get_type()
        if "PE32" not in ftype:
            log.info("Not a PE32 file, skipping ML analysis")
            return {
                    "class": "unknown",
                    "prediction": "unknown",
                }
        # Extract features from the PE file
        features = self.extract_features(self.file_path)
        # Make prediction
        model = joblib.load(self.options["static_model_path"])
        prediction = model.predict(features)
        # Get the predicted class
        if prediction[0] == 1:
            prediction_class = "malicious"
        else:
            prediction_class = "clean"
        result = {
                "class": prediction_class,
                "prediction": str(prediction[0]),
            }
        # Save the result to the results dictionary
        return result
        
       
    def run(self):
        """Run ML Detection Module."""
        bilstm_result = self.bilstm()
        random_forest_result = self.static_random_forest()
        # Combine results from both models
        # Save the results to the results dictionary
        final_result = "need more analysis"
        final_prediction = "need more analysis"
        if bilstm_result["class"] == random_forest_result["class"]:
            final_result = bilstm_result["class"]
            final_prediction = bilstm_result["prediction"]
        elif bilstm_result["class"] == "unknown":
            final_result = random_forest_result["class"]
            final_prediction = random_forest_result["prediction"]
        elif random_forest_result["class"] == "unknown":
            final_result = bilstm_result["class"]
            final_prediction = bilstm_result["prediction"]
        else:
            final_result = "need more analysis"
            final_prediction = "need more analysis"
    
        return {
            "ml_detection": {
                "class": final_result,
                "prediction": final_prediction,
            },
            "bilstm": bilstm_result,
            "static_random_forest": random_forest_result,
        }


        

        
        
        