import json
import os
from datetime import datetime, timedelta
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization

# Diccionario para almacenar usuarios y contraseñas
registered_users = {
    "Alice": "123",
    "Bob": "456",
    # Agrega más usuarios según sea necesario
}

# Función para cargar o generar claves
def load_or_generate_keys():
    if os.path.exists("private_key.pem") and os.path.exists("public_key.pem"):
        with open("private_key.pem", "rb") as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None)
        with open("public_key.pem", "rb") as f:
            public_key = serialization.load_pem_public_key(f.read())
    else:
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        public_key = private_key.public_key()
        save_keys(private_key, public_key)
    return private_key, public_key

# Guardar las claves en archivos para uso futuro
def save_keys(private_key, public_key):
    with open("private_key.pem", "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
        )
    with open("public_key.pem", "wb") as f:
        f.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )

# Función para autenticar usuarios
def authenticate_user():
    while True:
        username = input("¿Quién eres? ").strip()
        password = input("Ingresa tu contraseña: ").strip()

        if username in registered_users and registered_users[username] == password:
            return username
        else:
            print("Usuario o contraseña incorrectos. Inténtalo de nuevo.")

# Función para firmar archivos
def sign_file(file_path, private_key, signer_name):
    with open(file_path, "rb") as f:
        file_data = f.read()

    signature = private_key.sign(
        file_data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")  # Formato de fecha y hora
    signature_info = {
        "signer": signer_name,
        "timestamp": timestamp,
        "signature": signature.hex()
    }

    base_signature_path = f"{file_path}.signature"
    signature_path = base_signature_path
    counter = 1
    while os.path.exists(signature_path):
        signature_path = f"{base_signature_path}.{counter}"
        counter += 1

    with open(signature_path, "w") as f:
        json.dump(signature_info, f)

    print(f"Firma generada y guardada en: {signature_path}")
    return signature_path

# Función para verificar firmas de archivos
def verify_file(file_path, signature_hex, public_key):
    with open(file_path, "rb") as f:
        file_data = f.read()

    signature = bytes.fromhex(signature_hex)

    try:
        public_key.verify(
            signature,
            file_data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        print(f"La firma de {file_path} ha sido verificada exitosamente.")
    except Exception as e:
        print(f"La verificación de la firma de {file_path} ha fallado:", e)

# Función para firmar un PDF
def sign_pdf(pdf_path, private_key, signer_name):
    return sign_file(pdf_path, private_key, signer_name)

# Función para verificar un PDF
def verify_pdf(pdf_path, signature_hex, public_key):
    verify_file(pdf_path, signature_hex, public_key)

# Función para firmar un PNG
def sign_png(png_path, private_key, signer_name):
    return sign_file(png_path, private_key, signer_name)

# Función para verificar un PNG
def verify_png(png_path, signature_hex, public_key):
    verify_file(png_path, signature_hex, public_key)

# Función para firmar un JPG o JPEG
def sign_jpg(jpg_path, private_key, signer_name):
    return sign_file(jpg_path, private_key, signer_name)

# Función para verificar un JPG o JPEG
def verify_jpg(jpg_path, signature_hex, public_key):
    verify_file(jpg_path, signature_hex, public_key)

# Ejecución principal
def main():
    print("Bienvenido al sistema de firma electrónica.")
    username = authenticate_user()
    print(f"Bienvenido, {username}.")

    action = input("¿Qué deseas hacer, firmar o verificar? (firmar/verificar): ").strip().lower()

    private_key, public_key = load_or_generate_keys()

    if action == "firmar":
        file_path = input("Ingresa la ruta del archivo que deseas firmar. Solo se soportan archivos PDF, PNG, JPG y JPEG. (ej. C:\\Users\\TuNombre\\Documentos\\archivo.pdf): ").strip()
        if os.path.exists(file_path):
            if file_path.lower().endswith(".pdf"):
                signature_path = sign_pdf(file_path, private_key, username)
                print(f"El archivo {file_path} ha sido firmado exitosamente. Firma guardada en {signature_path}")
            elif file_path.lower().endswith(".png"):
                signature_path = sign_png(file_path, private_key, username)
                print(f"El archivo {file_path} ha sido firmado exitosamente. Firma guardada en {signature_path}")
            elif file_path.lower().endswith(".jpg") or file_path.lower().endswith(".jpeg"):
                signature_path = sign_jpg(file_path, private_key, username)
                print(f"El archivo {file_path} ha sido firmado exitosamente. Firma guardada en {signature_path}")
            else:
                print("Tipo de archivo no soportado. Solo se soportan archivos PDF, PNG, JPG y JPEG.")
        else:
            print(f"El archivo especificado no existe: {file_path}")
    elif action == "verificar":
        file_path = input("Ingresa la ruta del archivo que deseas verificar (ej. C:\\Users\\TuNombre\\Documentos\\archivo.pdf): ").strip()
        signature_hex = input("Ingresa la firma del archivo que deseas verificar: ").strip()
        if os.path.exists(file_path):
            if all(c in "0123456789abcdefABCDEF" for c in signature_hex):
                if file_path.lower().endswith(".pdf"):
                    verify_pdf(file_path, signature_hex, public_key)
                elif file_path.lower().endswith(".png"):
                    verify_png(file_path, signature_hex, public_key)
                elif file_path.lower().endswith(".jpg") or file_path.lower().endswith(".jpeg"):
                    verify_jpg(file_path, signature_hex, public_key)
                else:
                    print("Tipo de archivo no soportado. Solo se soportan archivos PDF, PNG, JPG y JPEG.")
            else:
                print("La firma proporcionada no es válida.")
        else:
            print(f"El archivo especificado no existe: {file_path}")
    else:
        print("Acción no reconocida. Por favor, elige 'firmar' o 'verificar'.")

if __name__ == "__main__":
    main()



