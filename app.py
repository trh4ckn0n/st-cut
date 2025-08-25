import streamlit as st
import io, zipfile
from Crypto.Cipher import AES
import hashlib

# ---------------- CONFIG -----------------
DEFAULT_CHUNK_MB = 10
CHUNK_SIZE = DEFAULT_CHUNK_MB * 1024 * 1024

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

def split_encrypt_stream(uploaded_file, filename, key, chunk_size=CHUNK_SIZE):
    uploaded_file.seek(0)
    parts = []
    hashes = []
    i = 0
    total_size = uploaded_file.size
    read_bytes = 0
    while True:
        chunk = uploaded_file.read(chunk_size)
        if not chunk:
            break
        cipher = AES.new(key, AES.MODE_CBC)
        ct_bytes = cipher.encrypt(pad(chunk))
        part_data = cipher.iv + ct_bytes
        parts.append((f"{filename}.part{i}", part_data, sha256_bytes(chunk)))
        i += 1
        read_bytes += len(chunk)
        yield parts[-1], read_bytes / total_size  # renvoie le dernier chunk et la progression

def merge_decrypt_stream(parts, key):
    data = b""
    for part_name, part_bytes, _ in sorted(parts, key=lambda x: x[0]):
        iv = part_bytes[:16]
        ct = part_bytes[16:]
        cipher = AES.new(key, AES.MODE_CBC, iv=iv)
        data += unpad(cipher.decrypt(ct))
    return data

# ---------------- STYLE HACKER -----------------
st.markdown("""
<style>
body { background-color: #0f0f0f; color: #00ff00; font-family: 'Courier New', monospace; }
h1,h2,h3,h4,h5,h6 { color: #00ffff; font-family: 'Courier New', monospace; animation: glow 1.5s infinite alternate; }
.stButton>button { background-color: #111111; color: #00ff00; border: 1px solid #00ff00; font-weight: bold; }
.stButton>button:hover { background-color: #00ff00; color: #0f0f0f; }
.stProgress>div>div>div>div { background-color: #00ff00; }
@keyframes glow {
  0% { text-shadow: 0 0 5px #00ffff, 0 0 10px #00ff00; }
  100% { text-shadow: 0 0 20px #00ffff, 0 0 30px #00ff00; }
}
</style>
""", unsafe_allow_html=True)

st.title("⚡ TUR-FU File Split & Secure Tool ⚡")

# ---------------- SPLIT & ENCRYPT -----------------
st.subheader("🔹 Split & Encrypt")
uploaded_file = st.file_uploader("Choose a file", key="split")
passphrase = st.text_input("Enter passphrase for encryption", type="password", key="split_pass")
chunk_size_input = st.number_input("Chunk size in MB", value=DEFAULT_CHUNK_MB, min_value=1, max_value=1024, key="chunk_size")
CHUNK_SIZE = int(chunk_size_input * 1024 * 1024)

if uploaded_file and passphrase:
    key = hashlib.sha256(passphrase.encode()).digest()
    parts_all = []
    progress_bar = st.progress(0.0)
    zip_buffer = io.BytesIO()
    
    try:
        with zipfile.ZipFile(zip_buffer, "w") as zipf:
            for (part_name, part_data, chunk_hash), progress in split_encrypt_stream(uploaded_file, uploaded_file.name, key, chunk_size=CHUNK_SIZE):
                zipf.writestr(part_name, part_data)
                st.write(f"{part_name} SHA256: `{chunk_hash}`")
                progress_bar.progress(progress)
                parts_all.append((part_name, part_data, chunk_hash))
        zip_buffer.seek(0)
        uploaded_file.seek(0)
        st.code(f"Original SHA256: {sha256_bytes(uploaded_file.read())}")
        st.download_button("Download all parts as ZIP", zip_buffer, file_name=f"{uploaded_file.name}_parts.zip")
        st.success(f"File split into **{len(parts_all)} encrypted parts**")
    except Exception as e:
        st.error(f"Error during split/encrypt: {e}")

# ---------------- MERGE & DECRYPT -----------------
st.subheader("🔹 Merge & Decrypt")
uploaded_parts = st.file_uploader("Upload all parts to merge", accept_multiple_files=True, key="merge")
merge_output_name = st.text_input("Output filename", value="reconstructed_file.dat", key="merge_name")
passphrase_merge = st.text_input("Enter passphrase for decryption", type="password", key="merge_pass")

if uploaded_parts and passphrase_merge and merge_output_name:
    key = hashlib.sha256(passphrase_merge.encode()).digest()
    parts_data = [(f.name, f.read(), None) for f in uploaded_parts]
    progress_bar_merge = st.progress(0.0)
    
    try:
        reconstructed = merge_decrypt_stream(parts_data, key)
        st.download_button(f"Download merged file ({merge_output_name})", io.BytesIO(reconstructed), file_name=merge_output_name)
        st.code(f"Reconstructed SHA256: {sha256_bytes(reconstructed)}")
        progress_bar_merge.progress(1.0)
    except Exception as e:
        st.error(f"Error during merge/decrypt: {e}")
