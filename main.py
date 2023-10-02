import random
import subprocess
from PIL import Image


def string_to_binary(input_string):
    bytes_data = input_string.encode('utf-8')
    binary_string = ''.join(format(byte, '08b') for byte in bytes_data)
    return binary_string


def binary_to_string(binary_string):
    bytes_data = [binary_string[i:i + 8] for i in range(0, len(binary_string), 8)]
    byte_values = [int(byte, 2) for byte in bytes_data]
    decoded_string = bytes(byte_values).decode('utf-8')
    return decoded_string


# Генерируем ключ для внедрения хеша в изображение
def generate_key(image_width, image_height, hash_length):
    num_pixels = image_width * image_height * 3
    key = random.sample(range(num_pixels), hash_length)
    return key


# Внедряем хеш в изображение с использованием заданного ключа
def embed_hash_in_image(input_image_path, output_image_path, hash_binary, key):
    image = Image.open(input_image_path)
    width, height = image.size

    if len(hash_binary) > len(key):
        print("Файл изображения слишком мал для хранения хеша")
        return

    pixel_data = list(image.getdata())
    embedded_image_data = []

    hash_index = 0

    for i, pixel in enumerate(pixel_data):
        r, g, b = pixel

        if hash_index < len(hash_binary) and i in key:
            bit_to_embed = int(hash_binary[hash_index])
            r = (r & 0xFE) | bit_to_embed
            hash_index += 1

        if hash_index < len(hash_binary) and i in key:
            bit_to_embed = int(hash_binary[hash_index])
            g = (g & 0xFE) | bit_to_embed
            hash_index += 1

        if hash_index < len(hash_binary) and i in key:
            bit_to_embed = int(hash_binary[hash_index])
            b = (b & 0xFE) | bit_to_embed
            hash_index += 1

        embedded_image_data.append((r, g, b))

    embedded_image = Image.new("RGB", (width, height))
    embedded_image.putdata(embedded_image_data)
    embedded_image.save(output_image_path)


# Извлекаем хеш из изображения с использованием заданного ключа.
def extract_hash_from_image(input_image_path, key, hash_length):
    image = Image.open(input_image_path)
    pixel_data = list(image.getdata())

    extracted_hash = ''
    hash_index = 0

    for i, pixel in enumerate(pixel_data):
        r, g, b = pixel

        if i in key:
            extracted_hash += str(r & 0x01)
            extracted_hash += str(g & 0x01)
            extracted_hash += str(b & 0x01)
            hash_index += 3

            if hash_index >= hash_length:
                break
    extracted_hash = extracted_hash[:hash_length]

    return extracted_hash


file_path = "leasing.txt"
image_path = "28.bmp"
output_image_path = "modified_28.bmp"

result = subprocess.run(["openssl", "dgst", "-sha1", file_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                        text=True)

if result.returncode == 0:
    sha1_hash = result.stdout.strip().split('= ')[1]
    print("SHA-1 хешкод файла:", sha1_hash)

    sha1_binary = string_to_binary(sha1_hash)

    # Получаем ширину и высоту изображения
    image = Image.open(image_path)
    image_width, image_height = image.size

    # Создаем ключ, основанный на ширине, высоте и длине хеша
    key = generate_key(image_width, image_height, len(sha1_binary))

    embed_hash_in_image(image_path, output_image_path, sha1_binary, key)
    print("Изображение с внедренным хешкодом сохранено как", output_image_path)

    extracted_hash = extract_hash_from_image(output_image_path, key, len(sha1_binary))

    print("Извлеченный хешкод из изображения:", binary_to_string(extracted_hash))

    if sha1_binary == extracted_hash:
        print("Успешное извлечение хешкода")
    else:
        print("Ошибка в извлечении хешкода!")

else:
    print("Ошибка выполнения команды OpenSSL:")
    print(result.stderr)
