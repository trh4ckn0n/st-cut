import streamlit as st
import io, zipfile, json, os, datetime
from Crypto.Cipher import AES
import hashlib

# ---------------- CONFIG -----------------
DEFAULT_CHUNK_MB = 10
CHUNK_SIZE = DEFAULT_CHUNK_MB * 1024 * 1024
REGISTRY_FILE = "file_registry.json"

# ---------------- UTILITAIRES -----------------
def pad(data):
    pad_len = 16 - len(data) % 16
    return data + bytes([pad_len])*pad_len

def unpad(data):
    return data[:-data[-1]]

def sha256_bytes(data):
    h = hashlib.sha256()
    h.update(data)
    return h.hexdigest()

def split_encrypt(file_bytes, filename, key, chunk_size=CHUNK_SIZE):
    buffer = io.BytesIO(file_bytes)
    parts = []
    i = 0
    total_size = len(file_bytes)
    read_bytes = 0
    while True:
        chunk = buffer.read(chunk_size)
        if not chunk:
            break
        cipher = AES.new(key, AES.MODE_CBC)
        ct_bytes = cipher.encrypt(pad(chunk))
        part_data = cipher.iv + ct_bytes
        parts.append((f"{filename}.part{i}", part_data, sha256_bytes(chunk)))
        i += 1
        read_bytes += len(chunk)
        yield parts[-1], read_bytes / total_size

def merge_decrypt(parts, key):
    data = b""
    for part_name, part_bytes, _ in sorted(parts, key=lambda x: x[0]):
        iv = part_bytes[:16]
        ct = part_bytes[16:]
        cipher = AES.new(key, AES.MODE_CBC, iv=iv)
        data += unpad(cipher.decrypt(ct))
    return data

def save_registry(entry):
    if os.path.exists(REGISTRY_FILE):
        with open(REGISTRY_FILE, "r") as f:
            registry = json.load(f)
    else:
        registry = []

    registry.append(entry)
    with open(REGISTRY_FILE, "w") as f:
        json.dump(registry, f, indent=2)

def load_registry():
    if os.path.exists(REGISTRY_FILE):
        with open(REGISTRY_FILE, "r") as f:
            return json.load(f)
    return []

# ---------------- STYLE ANONYMOUS DARK -----------------
st.markdown("""
<style>
body { background-color:#050505; color:#00ff00; font-family:'Courier New', monospace; }
h1,h2,h3 { color:#fff000; text-shadow:0 0 10px #ffff00,0 0 20px #00ff00; animation:flicker 1.5s infinite alternate; font-weight:bold; }
h4,h5,h6 { color:#00ffff; text-shadow:0 0 10px #ff0000,0 0 20px #00ff00; animation:flicker 1.5s infinite alternate; font-weight:bold; }
p  { color:#00ffff; text-shadow:0 0 10px #ff0000,0 0 20px #00ff00; animation:flicker 1.5s infinite alternate; font-weight:bold; }
li, span { color:#00ff00; }
.stButton>button { background-color:#111111; color:#00ff00; border:2px solid #00ff00; font-weight:bold; padding:0.5em 1em; text-transform:uppercase; transition:0.3s; }
.stButton>button:hover { background-color:#00ff00; color:#050505; box-shadow:0 0 10px #00ff00,0 0 20px #00ffff,0 0 30px #00ff00 inset; }
.stFileUploader>div { border:2px dashed #00ff00; border-radius:12px; padding:25px; background-color:#111111; transition:0.3s; }
.stFileUploader>div:hover { border-color:#00ffff; box-shadow:0 0 15px #00ff00,0 0 25px #00ffff inset; }
.stTextInput>div>div>input, .stTextArea>div>div>textarea, .stNumberInput>div>div>input { background-color:#111111; color:#00ff00; border:1px solid #00ff00; border-radius:5px; padding:5px; }
.stTextInput>div>div>input:focus, .stTextArea>div>div>textarea:focus, .stNumberInput>div>div>input:focus { border-color:#ff0000; outline:none; box-shadow:0 0 10px #ff0000,0 0 20px #00ff00 inset; }
.stProgress>div>div>div>div { background-color:#00ff00 !important; border-radius:6px; height:15px; }
.registry-entry { border:1px solid #00ff00; padding:15px; margin:5px 0; border-radius:8px; background-color:#111111; transition:0.3s; animation: entry-glitch 2s infinite alternate; }
.registry-entry:hover { border-color:#ff0000; box-shadow:0 0 15px #00ff00,0 0 30px #ff0000 inset; }
a { color:#00ffff; text-decoration:none; }
a:hover { text-decoration:underline; color:#00ff00; }
@keyframes flicker { 0% {opacity:0.9; text-shadow:0 0 5px #00ffff;} 50% {opacity:1; text-shadow:0 0 20px #00ff00,0 0 30px #ff0000;} 100% {opacity:0.95; text-shadow:0 0 10px #00ff00,0 0 20px #ff0000;} }
@keyframes entry-glitch { 0% { box-shadow:0 0 10px #00ff00,0 0 20px #ff0000; } 50% { box-shadow:0 0 15px #00ff00,0 0 25px #ff0000 inset; } 100% { box-shadow:0 0 12px #00ff00,0 0 22px #ff0000; } }
::-webkit-scrollbar { width:10px; }
::-webkit-scrollbar-track { background:#111111; }
::-webkit-scrollbar-thumb { background-color:#00ff00; border-radius:10px; border:2px solid #050505; }
</style>
""", unsafe_allow_html=True)

# ---------------- HEADER -----------------
st.title("⚡ TUR-FU PRO++ - trhacknon ⚡")
st.markdown("#### File Split & Secure Tool | Anonymous / Dark Mode")

# ---------------- SPLIT & ENCRYPT -----------------
st.subheader("🔹 Split & Encrypt")
uploaded_file = st.file_uploader("Choose a file", key="split")
passphrase = st.text_input("Enter passphrase for encryption", type="password", key="split_pass")
description = st.text_area("Add description or notes for this file", placeholder="E.g., Project backup, confidential, etc.")
chunk_size_input = st.number_input("Chunk size in MB", value=DEFAULT_CHUNK_MB, min_value=1, max_value=1024, key="chunk_size")
CHUNK_SIZE = int(chunk_size_input * 1024 * 1024)

if uploaded_file and passphrase:
    try:
        file_bytes = uploaded_file.read()
        key = hashlib.sha256(passphrase.encode()).digest()
        progress_bar = st.progress(0.0)
        zip_buffer = io.BytesIO()
        parts_all = []

        with zipfile.ZipFile(zip_buffer, "w") as zipf:
            for (part_name, part_data, chunk_hash), progress in split_encrypt(file_bytes, uploaded_file.name, key, chunk_size=CHUNK_SIZE):
                zipf.writestr(part_name, part_data)
                st.markdown(f"<span style='color:#00ffff'>[trhacknon]> Chunk {part_name} processed | SHA256: {chunk_hash}</span>", unsafe_allow_html=True)
                progress_bar.progress(progress)
                parts_all.append((part_name, part_data, chunk_hash))

        zip_buffer.seek(0)
        st.code(f"Original SHA256: {sha256_bytes(file_bytes)}")
        st.download_button("Download all parts as ZIP", zip_buffer, file_name=f"{uploaded_file.name}_parts.zip")
        st.success(f"File split into **{len(parts_all)} encrypted parts**")

        entry = {
            "filename": uploaded_file.name,
            "description": description,
            "size_bytes": len(file_bytes),
            "sha256": sha256_bytes(file_bytes),
            "chunks": len(parts_all),
            "chunk_size_bytes": CHUNK_SIZE,
            "date": str(datetime.datetime.now())
        }
        save_registry(entry)
        st.info(f"✅ File metadata saved. Total files in registry: {len(load_registry())}")
    except Exception as e:
        st.error(f"Error during split/encrypt: {e}")

# ---------------- MERGE & DECRYPT -----------------
# ---------------- MERGE & DECRYPT (suite complète) -----------------
st.subheader("🔹 Merge & Decrypt")
uploaded_zip_or_parts = st.file_uploader("Upload all parts (or ZIP containing parts)", accept_multiple_files=False, key="merge")
passphrase_merge = st.text_input("Enter passphrase for decryption", type="password", key="merge_pass")

if uploaded_zip_or_parts and passphrase_merge:
    try:
        key = hashlib.sha256(passphrase_merge.encode()).digest()
        uploaded_bytes = uploaded_zip_or_parts.read()
        parts_data = []

        if zipfile.is_zipfile(io.BytesIO(uploaded_bytes)):
            with zipfile.ZipFile(io.BytesIO(uploaded_bytes)) as zf:
                for f in zf.namelist():
                    parts_data.append((f, zf.read(f), None))
            base_name = parts_data[0][0].rsplit(".part", 1)[0]
            ext = "." + base_name.split(".")[-1] if "." in base_name else ""
        else:
            parts_data.append((uploaded_zip_or_parts.name, uploaded_bytes, None))
            base_name = uploaded_zip_or_parts.name
            ext = "." + base_name.split(".")[-1] if "." in base_name else ""

        merge_output_name = st.text_input("Output filename", value=f"{base_name}_reconstructed{ext}", key="merge_name")
        progress_bar_merge = st.progress(0.0)

        reconstructed = merge_decrypt(parts_data, key)
        st.download_button(f"Download merged file ({merge_output_name})", io.BytesIO(reconstructed), file_name=merge_output_name)
        st.code(f"Reconstructed SHA256: {sha256_bytes(reconstructed)}")
        progress_bar_merge.progress(1.0)
        st.success("Merge & decrypt completed successfully ✅")
    except Exception as e:
        st.error(f"Error during merge/decrypt: {e}")

# ---------------- REGISTRY VIEW -----------------
st.subheader("🗂 File Registry (trhacknon)")
registry = load_registry()
if registry:
    for idx, entry in enumerate(registry):
        st.markdown(f"<div class='registry-entry'>", unsafe_allow_html=True)
        st.markdown(f"**{idx+1}. {entry['filename']}** ({entry['chunks']} chunks, {entry['size_bytes']} bytes)")
        st.markdown(f"_SHA256_: `{entry['sha256']}`")
        st.markdown(f"_Description_: {entry['description']}")
        st.markdown(f"_Chunk size_: {entry['chunk_size_bytes']} bytes")
        st.markdown(f"_Date_: {entry['date']}")
        st.markdown("</div>", unsafe_allow_html=True)
else:
    st.info("No files in registry yet.")
