from pandas import *
from googletrans import Translator
import numpy as np
import matplotlib.pyplot as plt
import scipy.cluster.hierarchy as shc
from sklearn.cluster import AgglomerativeClustering
import datetime
from sklearn.cluster import KMeans
import time
import pyodbc
import pymssql

cnxn = pymssql.connect(server='SQL10\myserver', user='sa', password='Password!', database='Vulnerabilidades')
cursor = cnxn.cursor()


#lendo .xlsx ficheiro
df = read_excel('vullist.xlsx', sheet_name = 'Sheet', engine="openpyxl", skiprows=1, header=[1])

#Procure por registros de vulnerabilidades em firewalls e sistemas de detecção de intrusão
vulFW=df[df["Описание уязвимости"].str.contains("межсете")] 
vulIPS=df[df["Описание уязвимости"].str.contains("вторж")]
#vulCisco=df[df["Описание уязвимости"].str.contains("Cisco")]
#vulCisco=df[df["Описание уязвимости"].str.contains("Juniper")]

#Combine dois dataframes em um dataframe
vul = vulFW.append(vulIPS)

#Substituindo a lista de colunas no dataframe
vulFW=vulFW[['Идентификатор','Описание уязвимости','Дата выявления', 'Уровень опасности уязвимости']]
vulIPS=vulIPS[['Идентификатор','Описание уязвимости','Дата выявления', 'Уровень опасности уязвимости']]
vul=vul[['Идентификатор','Описание уязвимости','Дата выявления', 'Уровень опасности уязвимости']]
#print(vul)

#Pesquise e exclua duplicatas pela chave identificadora de vulnerabilidade do BDU
vul_dups = vul[vul.duplicated(keep='first')]
vul.drop_duplicates(subset='Идентификатор', keep='first', inplace=True)
print(vul_dups)
#print(vul)

def cases_in_year(year, vul): #função de pesquisa de vulnerabilidades identificadas para o ano especificado
    year=int(year)
    if year > 2020:
        return print('Especifique o ano entre 2015-2020')

    if (year % 4 == 0) and (year % 100 != 0) or (year % 400 == 0): #Verificando se há um ano bissexto
        days=366
    else:
        days=365
    f_date=datetime.datetime(year,1,1)
    interval = datetime.timedelta(days=days)
    sec_date=f_date+interval
    #vul['Дата выявления'] = to_datetime(vul['Дата выявления']).apply(lambda x: x.strftime('%Y-%m-%d %H:%M:%S') if not isnull(x) else '')
    vul['Дата выявления'] = to_datetime(vul['Дата выявления'], format='%d.%m.%Y')
    i=0
    for date in vul['Дата выявления']:
        if date is not None:
            if f_date <= date <= sec_date:
                i=i+1
        else:
            print(date)
    #print(i,'Casos em', year)
    return i
#Defina o ano de início da amostra
year=2015
#Inicio de os listos
x = []
y = []
y2 = []

for case in range(2021-year):
    y.append(cases_in_year(year, vulFW))
    y2.append(cases_in_year(year, vulIPS))
    year=year+1
    x.append(year)
#Traçando o número de vulnerabilidades descobertas nos últimos 5 anos
plt.title("Número de vulnerabilidades identificadas de FW e sistema de IDS") 
plt.xlabel("Anos")
plt.ylabel("Vulnerabilidades")
plt.grid()
plt.plot(x, y)           
plt.plot(x, y2) 
plt.legend(['FW', 'IDS'])
plt.show()

print(x)
print(y)
print(y2)
"""
y1 = np.random.randint(1, 10, size = 7)
y2 = np.random.randint(1, 10, size = 7)

fig, ax = plt.subplots()

ax.bar(x, y1)
ax.bar(x, y2)

ax.set_facecolor('seashell')
fig.set_figwidth(12)    #  ширина Figure
fig.set_figheight(6)    #  высота Figure
fig.set_facecolor('floralwhite')

plt.show()
"""
def gravidades(vul): #
    
    for n in vul['Уровень опасности уязвимости']:
        coor1=n.find('составляет')
        coor2=n.find(')')
        CVSS=n[coor1+11:coor2]
        CVSS=CVSS.replace(',', '.')
        vul.loc[vul['Уровень опасности уязвимости'] == n, 'CVSS'] = CVSS
    vul=vul[['Идентификатор','Описание уязвимости','Дата выявления', 'CVSS']]
    vul = vul.assign(CVSS=lambda d: d['CVSS'].astype(float))
    vul.columns = [c.replace(' ', '_') for c in vul.columns]
    vul['Дата_выявления'] = vul['Дата_выявления'].apply(lambda x: x.strftime('%Y-%m-%d')if not isnull(x) else '')
    return vul
vulFW=gravidades(vulFW)
x1=np.array(vulFW['CVSS'])
x1=x1.reshape(-1, 1)
y1=np.array(range(len(vulFW['CVSS'])))

vulIPS=gravidades(vulIPS)
x2=np.array(vulIPS['CVSS'])
x2=x2.reshape(-1, 1)
y2=np.array(range(len(vulIPS['CVSS'])))

def kmeans_plot(x, y):
    plt.scatter(x, y, label='Posição verdadeira')   
    plt.show() 
    kmeans = KMeans(n_clusters=4)
    kmeans.fit(x)
    print(kmeans.cluster_centers_)  
    plt.scatter(x,y, c=kmeans.labels_, cmap='rainbow')  
    plt.show()
kmeans_plot(x1, y1)
kmeans_plot(x2, y2)
def loadDF():
    for index, row in vulFW.iterrows():
        cursor.execute("INSERT INTO vullist_FW (Identificador,Descrição,Data_detecao,Avaliação) values(%s,%s,%s,%s)", (row.Идентификатор, row.Описание_уязвимости, row.Дата_выявления, row.CVSS))
    cnxn.commit()
    for index, row in vulIPS.iterrows():
        cursor.execute("INSERT INTO vullist_IDS (Identificador,Descrição,Data_detecao,Avaliação) values(%s,%s,%s,%s)", (row.Идентификатор, row.Описание_уязвимости, row.Дата_выявления, row.CVSS))
    cnxn.commit()
    cursor.close()
    print('Upload bem sucedido')
