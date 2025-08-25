import streamlit as st
import os, io, zipfile
from Crypto.Cipher import AES
import hashlib

CHUNK_SIZE = 10*1024*1024  # 10 Mo

# --------- Utilitaires ----------
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

# --------- CSS Hacker Theme ----------
st.markdown("""
<style>
body { background-color: #0f0f0f; color: #00ff00; }
h1,h2,h3,h4,h5,h6 { color: #00ffff; font-family: 'Courier New', monospace; }
.stButton>button { background-color: #111111; color: #00ff00; border: 1px solid #00ff00; font-weight: bold; }
.stButton>button:hover { background-color: #00ff00; color: #0f0f0f; }
.stProgress>div>div>div>div { background-color: #00ff00; }
</style>
""", unsafe_allow_html=True)

st.title("⚡ Ultra High-Tech File Split & Secure Tool ⚡")

# --------- Split & Encrypt ----------
st.subheader("🔹 Split & Encrypt")
uploaded_file = st.file_uploader("Choose a file", key="split")
passphrase = st.text_input("Enter passphrase for encryption", type="password", key="split_pass")

if uploaded_file and passphrase:
    key = hashlib.sha256(passphrase.encode()).digest()
    file_bytes = uploaded_file.read()
    parts = split_encrypt(file_bytes, uploaded_file.name, key)
    
    st.write(f"File split into **{len(parts)} encrypted parts**")
    st.write(f"Original SHA256: `{sha256_bytes(file_bytes)}`")
    
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w") as zipf:
        for part_name, part_data in parts:
            zipf.writestr(part_name, part_data)
    st.download_button("Download all parts as ZIP", zip_buffer.getvalue(), file_name=f"{uploaded_file.name}_parts.zip")

# --------- Merge & Decrypt ----------
st.subheader("🔹 Merge & Decrypt")
uploaded_parts = st.file_uploader("Upload all parts to merge", accept_multiple_files=True, key="merge")
merge_output_name = st.text_input("Output filename", value="reconstructed_file.dat", key="merge_name")
passphrase_merge = st.text_input("Enter passphrase for decryption", type="password", key="merge_pass")

if uploaded_parts and passphrase_merge and merge_output_name:
    key = hashlib.sha256(passphrase_merge.encode()).digest()
    parts_data = [(f.name, f.read()) for f in uploaded_parts]
    reconstructed = merge_decrypt(parts_data, key)
    
    st.download_button(f"Download merged file ({merge_output_name})", reconstructed, file_name=merge_output_name)
    st.write(f"Reconstructed SHA256: `{sha256_bytes(reconstructed)}`")
