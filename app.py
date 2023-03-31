from scapy.all import ARP, Ether, srp
import mysql.connector
from flask import Flask, request, render_template, redirect, url_for, jsonify, g
from flask_mysqldb import MySQL
from scapy.all import *
from scapy.layers.http import HTTPRequest
from scapy.layers.inet import *
from colorama import init, Fore
import subprocess
# from sn import analisis
import urllib.parse

ips = []
app = Flask(__name__)
datos_ip_g = []

# Definir la dirección IP y la máscara de red
ip = "192.168.89.0/24"

@app.before_first_request
def before_first_request():
    analiza_red()

# def obtener_data():
#     datos_ip = get_db()
#     datos_ip_g = datos_ip
#     print('Datos que contine DTOSP: ', datos_ip_g)
#     return datos_ip

@app.route('/',)
def index():
    datos_ip = get_db()
    lista_ip = ips

    print('ASI SE VEN LOS DATOS: ', datos_ip)

    return render_template('index.html', lista_ip=lista_ip, datos_ip=datos_ip)

def analiza_red():
    # Crear una solicitud ARP para cada dirección IP en la red
    arp = ARP(pdst=ip)
    # Crear una trama Ethernet para encapsular las solicitudes ARP
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp
    result = srp(packet, timeout=3, verbose=0)[0]
    clientes = []
    for enviado, recibido in result:
        clientes.append({recibido.psrc, recibido.hwsrc})

    for sent, received in result:
        # print(f"IP: {received.psrc} - MAC: {received.hwsrc}")
        ips.append(received.psrc)
    print(clientes)
    print('IPS: ', ips)
    ip_db(ips)


def ip_db(ips):
    print('Entrando a ufnicon para db', ips)
    mydb = mysql.connector.connect(
        host="localhost",
        user="root",
        password="0123456",
        database="analizador_red"
    )

    mycursor = mydb.cursor()

    for ip in ips:
        sql = "INSERT INTO analizador_red.ips (ip) VALUES (%s)"
        val = (ip,)
        mycursor.execute(sql, val)
        mydb.commit()

    mydb.close()

    print('Datos agregados a la BD')

@app.route('/analizar_red', methods=['POST'])
def ejecutarAnalsis():
    subprocess.run(['python', 'C:/Users/alanv/Desktop/proyc3/app/sn.py'])
    return ('Analizando trafico')

@app.route('/ver_datos', methods=['GET'])
def get_db():
    mydb = mysql.connector.connect(
    host="localhost",
    user="root",
    password="0123456",
    database="analizador_red"
)
    mycursor = mydb.cursor()

    sql = 'SELECT ip_origen, destino, user, password FROM datos_ip' 
    mycursor.execute(sql)
    datos_ip=mycursor.fetchall()  
    # print('ASI SE VEN LOS DATOS', datos_ip)
    return datos_ip

    # app.config['MYSQL_HOST'] = 'localhost'
    # app.config['MYSQL_USER'] = 'root'
    # app.config['MYSQL_PASSWORD'] = '0123456'
    # app.config['MYSQL_DB'] = 'analizador_red'

    # conexion = MySQL(app)
    # data = {}
    # cursor=conexion.connection.cursor()
    # sql = 'SELECT ip_origen, destino, user, password FROM datos_ip'
    # cursor.execute(sql)

if __name__ == '__main__':
    app.run(debug=True, port=3000)


def analizar_ip(data):
    pass
