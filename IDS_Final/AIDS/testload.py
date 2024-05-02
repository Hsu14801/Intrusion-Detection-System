# -*- coding: utf-8 -*-
"""
Created on Sun Jan 21 13:39:33 2024

@author: USER
"""
from evalml.automl import AutoMLSearch
import pandas as pd
import pickle

# with open('Cicid2018.pkl', 'rb') as f:
#     model = pickle.load(f)

automl = AutoMLSearch.load("Cicid2018.pkl")

df= pd.read_csv("test.csv")
# df = df.iloc[:,:-1]
# df.to_csv("test.csv", index = True)
y = automl.predict(df)

print(y)