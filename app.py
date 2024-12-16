import base64
import tkinter as tk
from tkinter import messagebox
from cifrado import encrypt_message, decrypt_message, generate_key
from verificacion_hmac import generate_hmac, verify_hmac

# Inicializar la clave AES
clave_aes = generate_key()


def crear_interfaz():
    """Crea la interfaz gráfica de la aplicación."""
    ventana_app = tk.Tk()  # Cambiar el nombre a ventana_app
    ventana_app.title("Cifrado de Mensajes")
    ventana_app.geometry("500x500")

    # Entradas y botones
    tk.Label(ventana_app, text="Mensaje a cifrar:").pack(pady=10)
    entrada_mensaje = tk.Entry(ventana_app, width=50)
    entrada_mensaje.pack(pady=5)

    # Resultado del cifrado (usando Text en lugar de Label)
    tk.Label(ventana_app, text="Mensaje Cifrado y HMAC:").pack(pady=10)
    texto_resultado_cifrado = tk.Text(ventana_app, height=4, width=50)
    texto_resultado_cifrado.pack(pady=5)
    texto_resultado_cifrado.config(state=tk.DISABLED)  # Deshabilitar la edición

    # Botón para cifrar
    tk.Button(ventana_app, text="Cifrar", command=lambda: cifrar(entrada_mensaje, texto_resultado_cifrado)).pack(
        pady=10)

    # Etiqueta y campo de entrada para el mensaje cifrado
    tk.Label(ventana_app, text="Ingrese el mensaje cifrado:").pack(pady=10)
    entrada_mensaje_cifrado = tk.Entry(ventana_app, width=50)
    entrada_mensaje_cifrado.pack(pady=5)

    # Etiqueta y campo de entrada para el HMAC
    tk.Label(ventana_app, text="HMAC:").pack(pady=10)
    entrada_hmac = tk.Entry(ventana_app, width=50)
    entrada_hmac.pack(pady=5)

    # Resultado del desciframiento
    resultado_descifrado = tk.StringVar()  # Definir resultado_descifrado aquí
    tk.Label(ventana_app, textvariable=resultado_descifrado).pack(pady=10)

    # Botón para descifrar
    tk.Button(ventana_app, text="Descifrar",
              command=lambda: descifrar(entrada_mensaje_cifrado, entrada_hmac, resultado_descifrado)).pack(pady=10)

    return ventana_app


def cifrar(entrada_mensaje, texto_resultado_cifrado):
    """Cifra el mensaje ingresado y muestra el resultado."""
    mensaje = entrada_mensaje.get()

    if not mensaje:
        messagebox.showwarning("Advertencia", "Por favor, ingrese un mensaje.")
        return

    hmac = generate_hmac(mensaje.encode(), clave_aes)  # Generar HMAC
    mensaje_cifrado = encrypt_message(clave_aes, mensaje)  # Cifrar mensaje

    # Mostrar el resultado en la interfaz
    texto_resultado_cifrado.config(state=tk.NORMAL)  # Habilitar la edición temporalmente
    texto_resultado_cifrado.delete(1.0, tk.END)  # Limpiar contenido anterior
    texto_resultado_cifrado.insert(tk.END, f'Mensaje Cifrado: {mensaje_cifrado}\nHMAC: {hmac.hex()}')
    texto_resultado_cifrado.config(state=tk.DISABLED)  # Deshabilitar la edición nuevamente


def descifrar(entrada_mensaje_cifrado, entrada_hmac, resultado_descifrado):
    mensaje_cifrado = entrada_mensaje_cifrado.get()

    try:
        hmac_usuario = bytes.fromhex(entrada_hmac.get())  # Convertir HMAC ingresado a bytes

        if not mensaje_cifrado or not entrada_hmac.get():
            messagebox.showwarning("Advertencia", "Por favor, ingrese un mensaje cifrado y HMAC.")
            return

        # Decodificar el mensaje cifrado
        mensaje_cifrado_bytes = base64.b64decode(mensaje_cifrado)

        # Verificar HMAC con el mensaje original antes de cifrar
        if not verify_hmac(mensaje_cifrado_bytes[16:], hmac_usuario, clave_aes):
            messagebox.showerror("Error", "El HMAC no es válido. El mensaje puede haber sido alterado.")
            return

        # Descifrar el mensaje
        mensaje_descifrado = decrypt_message(clave_aes, mensaje_cifrado)

        # Mostrar el resultado en la interfaz
        resultado_descifrado.set(f'Mensaje Descifrado: {mensaje_descifrado}')

    except ValueError as ve:
        messagebox.showerror("Error", str(ve))
    except Exception as e:
        messagebox.showerror("Error", f"Ocurrió un error al descifrar: {str(e)}")


# Ejecutar la aplicación
ventana = crear_interfaz()
ventana.mainloop()
