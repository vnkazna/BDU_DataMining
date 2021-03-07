from pandas import *
import pandas.io.sql as psql
import numpy as np
import matplotlib.pyplot as plt
import pymssql
from pylab import plot, show
import numpy as np

cnxn = pymssql.connect(server='SQL10\myserver', user='sa', password='Password!', database='Vulnerabilidades')
cursor = cnxn.cursor()

sql1 = ("SELECT * FROM vullist_IDS")
sql2 = ("SELECT * FROM vullist_FW")
df_IDS = psql.read_sql(sql1, cnxn)
df_FW = psql.read_sql(sql2, cnxn)
cnxn.close()
#print(df_IDS)
train_len = int(np.ceil(len(df_IDS) * 0.75))
train=train=df_IDS[0:train_len] 
test=df_IDS[train_len:]
print('Train data length :',len(train))
print('Test  data length :',len(test))[0:train_len] 

