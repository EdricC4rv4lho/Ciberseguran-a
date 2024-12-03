import random
import math

# Funções auxiliares para RSA


def is_prime(n):
    """Verifica se um número é primo"""
    if n <= 1:
        return False
    for i in range(2, int(math.sqrt(n)) + 1):
        if n % i == 0:
            return False
    return True


def generate_keys(p, q):
    """Gera as chaves públicas e privadas para RSA dado dois números primos"""
    n = p * q
    phi_n = (p - 1) * (q - 1)

    # Encontra e escolhe o valor de e (public exponent)
    e = 3
    while math.gcd(e, phi_n) != 1:
        e += 2

    # Calcula o valor de d (private exponent)
    d = modinv(e, phi_n)

    # Chaves pública e privada
    return ((e, n), (d, n))


def modinv(a, m):
    """Calcula o inverso modular de a mod m"""
    g, x, y = extended_gcd(a, m)
    if g != 1:
        raise Exception('O inverso modular não existe')
    return x % m


def extended_gcd(a, b):
    """Algoritmo de Euclides estendido"""
    if a == 0:
        return b, 0, 1
    g, y, x = extended_gcd(b % a, a)
    return g, x - (b // a) * y, y


def encrypt_rsa(message, public_key):
    """Criptografa uma mensagem usando a chave pública do RSA"""
    e, n = public_key
    return [pow(ord(char), e, n) for char in message]


def decrypt_rsa(ciphertext, private_key):
    """Descriptografa uma mensagem usando a chave privada do RSA"""
    d, n = private_key
    return ''.join([chr(pow(char, d, n)) for char in ciphertext])

# Funções para DES simplificado


def xor_bytes(byte1, byte2):
    """Realiza uma operação XOR entre dois bytes"""
    return bytes([b1 ^ b2 for b1, b2 in zip(byte1, byte2)])


def encrypt_des(message, key):
    """Criptografia DES simplificada (não real)"""
    key = key[:8]  # A chave DES possui 8 bytes
    encrypted_message = xor_bytes(message.encode(), key.encode())
    return encrypted_message


def decrypt_des(ciphertext, key):
    """Descriptografia DES simplificada (não real)"""
    key = key[:8]  # A chave DES possui 8 bytes
    decrypted_message = xor_bytes(ciphertext, key.encode())
    return decrypted_message.decode()

# Função principal de interação com o usuário


def main():
    print("Escolha o tipo de criptografia:")
    print("1. Criptografia Simétrica (DES)")
    print("2. Criptografia Assimétrica (RSA)")
    option = int(input("Digite a opção (1 ou 2): "))

    if option == 1:
        print("Criptografia Simétrica (DES)")
        mode = input(
            "Digite 'E' para criptografar ou 'D' para descriptografar: ").upper()
        message = input("Digite a mensagem: ")
        key = input("Digite a chave (8 caracteres): ")

        if mode == 'E':
            encrypted_message = encrypt_des(message, key)
            print(f"Mensagem criptografada (DES): {encrypted_message}")
        elif mode == 'D':
            decrypted_message = decrypt_des(message.encode(), key)
            print(f"Mensagem descriptografada (DES): {decrypted_message}")

    elif option == 2:
        print("Criptografia Assimétrica (RSA)")
        p = int(input("Digite o primeiro número primo: "))
        q = int(input("Digite o segundo número primo: "))

        if not is_prime(p) or not is_prime(q):
            print("Os números fornecidos não são primos.")
            return

        public_key, private_key = generate_keys(p, q)
        print(f"Chave pública gerada: {public_key}")
        print(f"Chave privada gerada: {private_key}")

        mode = input(
            "Digite 'E' para criptografar ou 'D' para descriptografar: ").upper()
        message = input("Digite a mensagem: ")

        if mode == 'E':
            encrypted_message = encrypt_rsa(message, public_key)
            print(f"Mensagem criptografada (RSA): {encrypted_message}")
        elif mode == 'D':
            ciphertext = list(map(int, input(
                "Digite os valores criptografados (separados por espaço): ").split()))
            decrypted_message = decrypt_rsa(ciphertext, private_key)
            print(f"Mensagem descriptografada (RSA): {decrypted_message}")


if __name__ == "__main__":
    main()
