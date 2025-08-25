import streamlit as st
import os
from Crypto.Cipher import AES
import hashlib
from io import BytesIO

CHUNK_SIZE = 10 * 1024 * 1024  # 10 Mo

def pad(data):
    pad_len = 16 - len(data) % 16
    return data + bytes([pad_len])*pad_len

def unpad(data):
    return data[:-data[-1]]

def sha256_bytes(data):
    h = hashlib.sha256()
    h.update(data)
    return h.hexdigest()

def split_encrypt(file_bytes, filename, key):
    parts = []
    i = 0
    for j in range(0, len(file_bytes), CHUNK_SIZE):
        chunk = file_bytes[j:j+CHUNK_SIZE]
        cipher = AES.new(key, AES.MODE_CBC)
        ct_bytes = cipher.encrypt(pad(chunk))
        part_data = cipher.iv + ct_bytes
        part_name = f"{filename}.part{i}"
        parts.append((part_name, part_data))
        i += 1
    return parts

def merge_decrypt(parts, key):
    data = b""
    for part_name, part_bytes in sorted(parts, key=lambda x: x[0]):
        iv = part_bytes[:16]
        ct = part_bytes[16:]
        cipher = AES.new(key, AES.MODE_CBC, iv=iv)
        data += unpad(cipher.decrypt(ct))
    return data

st.title("Ultra High-Tech File Split & Secure Tool")

st.subheader("Upload file to split")
uploaded_file = st.file_uploader("Choose a file", type=None)

passphrase = st.text_input("Enter passphrase for encryption", type="password")

if uploaded_file and passphrase:
    key = hashlib.sha256(passphrase.encode()).digest()
    file_bytes = uploaded_file.read()
    parts = split_encrypt(file_bytes, uploaded_file.name, key)
    
    st.write(f"File split into {len(parts)} encrypted parts")
    
    # Show SHA256 of original
    st.write(f"Original file SHA256: {sha256_bytes(file_bytes)}")
    
    for part_name, part_data in parts:
        st.download_button(
            label=f"Download {part_name}",
            data=part_data,
            file_name=part_name,
            mime="application/octet-stream"
        )

st.subheader("Merge encrypted parts")
uploaded_parts = st.file_uploader("Upload all parts to merge", accept_multiple_files=True)
merge_output_name = st.text_input("Output filename", value="reconstructed_file.dat")

if uploaded_parts and passphrase and merge_output_name:
    key = hashlib.sha256(passphrase.encode()).digest()
    parts_data = [(f.name, f.read()) for f in uploaded_parts]
    reconstructed = merge_decrypt(parts_data, key)
    st.download_button(
        label=f"Download merged file ({merge_output_name})",
        data=reconstructed,
        file_name=merge_output_name,
        mime="application/octet-stream"
    )
    st.write(f"Reconstructed file SHA256: {sha256_bytes(reconstructed)}")
