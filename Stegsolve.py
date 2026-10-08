import cv2
import numpy as np
import os
import subprocess
import re
import sys
import argparse
import datetime
from tqdm import tqdm
import shutil
import glob
import zlib
import struct
import hashlib
import base64
import codecs
import urllib.parse
import html
import string
import json
from typing import Optional, List, Dict, Set, Any

class StegoAnalyzer:
    def __init__(self, file_path: str, output_dir: Optional[str] = None, save_separate: bool = True,
                 passphrase: Optional[str] = None, wordlist: Optional[str] = None, zsteg_all: bool = False,
                 open_browser: bool = True) -> None:
        self.file_path = os.path.abspath(file_path)
        self.save_separate = save_separate
        self.passphrase = passphrase
        self.wordlist = wordlist
        self.zsteg_all = zsteg_all
        self.open_browser = open_browser
        self.file_hash = self._calculate_sha256()
        self.extracted_files_meta: List[Dict[str, Any]] = []
        self.decoded_findings: List[Dict[str, Any]] = []
        
        if output_dir is None:
            base_name = os.path.splitext(os.path.basename(file_path))[0]
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            self.output_dir = f"{base_name}_{timestamp}_reports"
        else:
            self.output_dir = output_dir
            
        self.file_type = self._get_file_type()
        
        # CTF Bayrak formatlarını yakalamak için Regex
        # İstikrarlı olması için ön ekin en az 3, iç kısmın en az 4 karakter olması şartı konuldu
        self.flag_pattern = re.compile(r'[a-zA-Z0-9_]{3,30}{[a-zA-Z0-9_!@#$%^&*()-=+\\]{4,}}')
        
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)
            
        self.bit_planes_dir = os.path.join(self.output_dir, "bit_planes")
        if not os.path.exists(self.bit_planes_dir):
            os.makedirs(self.bit_planes_dir)
            
        # Sözlük yükle (Anlamlı kelime tespiti için)
        self.dictionary: Set[str] = set()
        unix_dict_path = "/usr/share/dict/words"
        local_dict_path = "words.txt"
        
        if os.path.exists(local_dict_path):
            with open(local_dict_path, "r", encoding="utf-8", errors="ignore") as f:
                self.dictionary = set(word.strip().lower() for word in f if len(word.strip()) > 3)
        elif os.path.exists(unix_dict_path):
            with open(unix_dict_path, "r", encoding="utf-8", errors="ignore") as f:
                self.dictionary = set(word.strip().lower() for word in f if len(word.strip()) > 3)
        else:
            print("[-] Uyarı: Sözlük dosyası bulunamadı! Anlamlı cümle analizi devre dışı bırakıldı.")
            print("[*] Bu özelliği kullanmak için lütfen programın bulunduğu dizine İngilizce kelimeleri içeren bir 'words.txt' dosyası oluşturun.\n")

    def _get_file_type(self) -> str:
        """Dosyanın video, fotoğraf veya ses mi olduğunu belirler."""
        video_exts = ['.mp4', '.avi', '.mov', '.mkv']
        img_exts = ['.png', '.jpg', '.jpeg', '.bmp', '.tiff', '.webp']
        audio_exts = ['.wav', '.au', '.mp3', '.ogg', '.flac']
        ext = os.path.splitext(self.file_path)[1].lower()
        
        if ext in video_exts:
            return "video"
        elif ext in img_exts:
            return "image"
        elif ext in audio_exts:
            return "audio"
        else:
            return "unknown"

    def _find_executable(self, name: str) -> Optional[str]:
        """Komutun sistem PATH'inde veya bilinen kullanıcı/gem dizinlerinde olup olmadığını tespit eder."""
        path = shutil.which(name)
        if path:
            return path
        
        extra_dirs = [
            "/usr/local/bin",
            "/usr/bin",
            "/bin",
            "/opt/homebrew/bin",
            "/opt/local/bin",
            os.path.expanduser("~/.local/bin")
        ]
        # Ruby gem dizinleri (zsteg için)
        extra_dirs.extend(glob.glob(os.path.expanduser("~/.gem/ruby/*/bin")))

        for d in extra_dirs:
            candidate = os.path.join(d, name)
            if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
                return candidate
        return None

    def _calculate_sha256(self) -> str:
        """Hedef dosyanın SHA256 özetini hesaplar."""
        try:
            h = hashlib.sha256()
            with open(self.file_path, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    h.update(chunk)
            return h.hexdigest()
        except Exception:
            return "N/A"

    def check_and_fix_png_ihdr(self) -> None:
        """PNG dosyasının IHDR CRC ve boyut bütünlüğünü inceler, bozukluk varsa gerçek boyutları hesaplar."""
        print("[+] PNG IHDR Chunk ve CRC bütünlük kontrolü yapılıyor...")
        try:
            with open(self.file_path, "rb") as f:
                data = f.read()

            if len(data) < 29 or data[:8] != b'\x89PNG\r\n\x1a\n':
                return

            ihdr_len = struct.unpack('>I', data[8:12])[0]
            if data[12:16] != b'IHDR' or ihdr_len != 13:
                return

            ihdr_data = data[16:16+ihdr_len]
            stored_crc = struct.unpack('>I', data[16+ihdr_len:20+ihdr_len])[0]
            calc_crc = zlib.crc32(b'IHDR' + ihdr_data) & 0xffffffff

            w, h, bit_depth, color_type, comp, filt, inter = struct.unpack('>IIBBBBB', ihdr_data)
            rest_bytes = struct.pack('>BBBBB', bit_depth, color_type, comp, filt, inter)

            if calc_crc == stored_crc:
                print(f"[+] PNG IHDR CRC doğrulaması başarılı ({w}x{h}, CRC: {stored_crc:#010x}).")
            else:
                print(f"\n[!!!] DİKKAT: PNG IHDR CRC UYUMSUZLUĞU TESPİT EDİLDİ!")
                print(f"      Mevcut Görünür Boyut: {w}x{h}")
                print(f"      Kayıtlı CRC : {stored_crc:#010x} | Hesaplanan: {calc_crc:#010x}")
                print("[*] Gerçek boyutlar CRC üzerinden hesaplanıyor...")

                found_w, found_h = None, None
                # 1. Adım: Genişlik doğru, yükseklik kırpılmış senaryosu (en yaygın CTF stego numarası)
                for test_h in range(1, 25001):
                    test_payload = b'IHDR' + struct.pack('>II', w, test_h) + rest_bytes
                    if (zlib.crc32(test_payload) & 0xffffffff) == stored_crc:
                        found_w, found_h = w, test_h
                        break

                # 2. Adım: Yükseklik doğru, genişlik değiştirilmiş senaryosu
                if not found_h:
                    for test_w in range(1, 25001):
                        test_payload = b'IHDR' + struct.pack('>II', test_w, h) + rest_bytes
                        if (zlib.crc32(test_payload) & 0xffffffff) == stored_crc:
                            found_w, found_h = test_w, h
                            break

                if found_w and found_h:
                    print(f"[!!!] BAŞARILI! Gerçek PNG Boyutları Bulundu: {found_w}x{found_h}!")
                    fixed_data = data[:16] + struct.pack('>II', found_w, found_h) + data[24:]
                    fixed_file = os.path.join(self.output_dir, "fixed_dimensions.png")
                    with open(fixed_file, "wb") as ff:
                        ff.write(fixed_data)
                    print(f"[+] Düzeltilmiş görsel oluşturuldu: {fixed_file}")
                    
                    with open(os.path.join(self.output_dir, "FOUND_FLAGS.txt"), "a", encoding="utf-8") as fl:
                        fl.write(f"\n--- PNG Boyut Onarımı (IHDR CRC) ---\n")
                        fl.write(f"Orijinal Bozuk Boyut: {w}x{h} -> Düzeltilen Gerçek Boyut: {found_w}x{found_h}\n")
                        fl.write(f"Düzeltilmiş Dosya: {fixed_file}\n")
                else:
                    print("[-] Boyut brute-force aralığında otomatik tespit edilemedi.")

            # PNG IEND Sonrası Fazlalık (Trailing / Overlay Data) Kontrolü
            iend_idx = data.find(b'IEND')
            if iend_idx != -1:
                iend_end = iend_idx + 8  # 'IEND' (4 byte) + CRC (4 byte)
                if iend_end < len(data):
                    trailing = data[iend_end:]
                    trailing_path = os.path.join(self.output_dir, "png_trailing_data.bin")
                    with open(trailing_path, "wb") as tf:
                        tf.write(trailing)
                    print(f"\n[!] PNG IEND Sonrası {len(trailing)} byte fazladan veri (Overlay) tespit edildi!")
                    print(f"    Kaydedildi: {trailing_path}")
                    try:
                        t_text = trailing.decode('utf-8', errors='ignore')
                        self._search_flags_in_text("PNG Trailing Data", t_text)
                    except Exception:
                        pass
        except Exception as e:
            print(f"[-] PNG IHDR kontrol hatası: {e}")

    def check_and_fix_jpeg_dimensions(self) -> None:
        """JPEG dosyasında SOF (Start of Frame) boyut manipülasyonlarını (kırpma/yükseklik gizleme)
        Exif/XMP metadata ve DCT tarama anomalileri ile karşılaştırarak tespit eder ve görseli onarır."""
        print("[+] JPEG Boyut Bütünlüğü ve SOF Marker (Yükseklik/Genişlik) kontrolü yapılıyor...")
        try:
            with open(self.file_path, "rb") as f:
                data = bytearray(f.read())

            if len(data) < 4 or data[:2] != b'\xff\xd8':
                return

            # SOF Marker'larını Tara (0xC0: Baseline, 0xC1: Extended, 0xC2: Progressive, vb.)
            sof_markers = [0xC0, 0xC1, 0xC2, 0xC3, 0xC9, 0xCA, 0xCB]
            pos = 2
            primary_sof = None  # (offset, marker_byte, precision, height, width, components)

            while pos < len(data) - 4:
                if data[pos] == 0xFF:
                    m = data[pos + 1]
                    if m in [0xD8, 0xD9, 0x00]:
                        pos += 2
                        continue
                    if pos + 4 > len(data):
                        break
                    length = (data[pos + 2] << 8) | data[pos + 3]
                    if m in sof_markers and length >= 8:
                        precision = data[pos + 4]
                        height = (data[pos + 5] << 8) | data[pos + 6]
                        width = (data[pos + 7] << 8) | data[pos + 8]
                        components = data[pos + 9]
                        primary_sof = (pos, m, precision, height, width, components)
                        break
                    pos += 2 + length
                else:
                    pos += 1

            if not primary_sof:
                return

            sof_pos, sof_marker, precision, cur_h, cur_w, components = primary_sof

            # 1. Exif/XMP Boyutlarını Çıkar
            exif_w, exif_h = None, None

            # 1.a) APP1 Exif TIFF Taglarını Doğrudan Parse Et (Sıfır Dış Bağımlılık)
            pos_scan = 2
            while pos_scan < len(data) - 4:
                if data[pos_scan] == 0xFF and data[pos_scan + 1] == 0xE1:
                    app1_len = (data[pos_scan + 2] << 8) | data[pos_scan + 3]
                    app1_payload = data[pos_scan + 4 : pos_scan + 2 + app1_len]
                    if app1_payload.startswith(b"Exif\x00\x00"):
                        tiff = app1_payload[6:]
                        if len(tiff) >= 8:
                            endian = "<" if tiff[:2] == b"II" else ">"
                            for i in range(0, len(tiff) - 12, 2):
                                try:
                                    tag = struct.unpack(endian + "H", tiff[i : i + 2])[0]
                                    if tag in [0xA002, 0x0100]:  # PixelXDimension veya ImageWidth
                                        val = struct.unpack(endian + "I", tiff[i + 8 : i + 12])[0]
                                        if 10 <= val <= 30000:
                                            exif_w = val
                                    elif tag in [0xA003, 0x0101]:  # PixelYDimension veya ImageLength
                                        val = struct.unpack(endian + "I", tiff[i + 8 : i + 12])[0]
                                        if 10 <= val <= 30000:
                                            exif_h = val
                                except Exception:
                                    pass
                    pos_scan += 2 + app1_len
                elif data[pos_scan] == 0xFF:
                    m = data[pos_scan + 1]
                    if m in [0xD8, 0xD9, 0x00]:
                        pos_scan += 2
                        continue
                    l = (data[pos_scan + 2] << 8) | data[pos_scan + 3]
                    pos_scan += 2 + l
                else:
                    pos_scan += 1

            # 1.b) Eğer Exif tag bulunamadıysa ExifTool CLI ile dene
            if not (exif_w and exif_h):
                exiftool_bin = self._find_executable('exiftool')
                if exiftool_bin:
                    try:
                        res = subprocess.run([exiftool_bin, '-ExifImageWidth', '-ExifImageHeight', '-s3', self.file_path],
                                             capture_output=True, text=True, errors="ignore")
                        lines = [ln.strip() for ln in res.stdout.splitlines() if ln.strip()]
                        if len(lines) >= 2:
                            w_cand, h_cand = int(lines[0]), int(lines[1])
                            if w_cand > 0: exif_w = w_cand
                            if h_cand > 0: exif_h = h_cand
                    except Exception:
                        pass

            # 1.c) XMP Metadata Regex Kontrolü
            if not (exif_w and exif_h):
                try:
                    raw_str = bytes(data).decode('latin1', errors='ignore')
                    mw = re.search(r'PixelXDimension\s*=\s*["\']?(\d+)', raw_str) or re.search(r'ExifImageWidth\s*=\s*["\']?(\d+)', raw_str)
                    mh = re.search(r'PixelYDimension\s*=\s*["\']?(\d+)', raw_str) or re.search(r'ExifImageHeight\s*=\s*["\']?(\d+)', raw_str)
                    if mw and not exif_w: exif_w = int(mw.group(1))
                    if mh and not exif_h: exif_h = int(mh.group(1))
                except Exception:
                    pass

            target_h = cur_h
            target_w = cur_w
            is_anomaly = False
            reason = ""

            if exif_h and exif_h > cur_h:
                target_h = exif_h
                is_anomaly = True
                reason = f"Exif metadata yüksekliği ({exif_h}px), SOF başlığından ({cur_h}px) daha büyük!"

            if exif_w and exif_w > cur_w:
                target_w = exif_w
                is_anomaly = True
                reason += f" Exif genişliği ({exif_w}px), SOF başlığından ({cur_w}px) daha büyük!"

            # 2. Extraneous Bytes Durumunda Otomatik Boyut Onarımı (Exif silinmiş olsa bile)
            if not is_anomaly:
                steghide_rep = os.path.join(self.output_dir, "steghide_report.txt")
                has_extraneous = False
                if os.path.exists(steghide_rep):
                    try:
                        with open(steghide_rep, "r", encoding="utf-8", errors="ignore") as rf:
                            if "extraneous bytes before marker" in rf.read():
                                has_extraneous = True
                    except Exception:
                        pass
                
                if has_extraneous:
                    djpeg_bin = self._find_executable('djpeg')
                    for add_h in [16, 32, 36, 48, 64, 96, 128, int(cur_h * 0.1), int(cur_h * 0.2)]:
                        test_h = cur_h + add_h
                        test_data = bytearray(data)
                        test_data[sof_pos + 5 : sof_pos + 7] = struct.pack(">H", test_h)
                        if djpeg_bin:
                            try:
                                chk = subprocess.run([djpeg_bin, '-v'], input=bytes(test_data), capture_output=True)
                                if b"extraneous bytes" not in chk.stderr:
                                    target_h = test_h
                                    is_anomaly = True
                                    reason = f"Extraneous bytes uyarısını sıfırlayan gerçek yükseklik bulundu (+{add_h}px -> {test_h}px)"
                                    break
                            except Exception:
                                pass

            if is_anomaly and (target_h != cur_h or target_w != cur_w):
                print(f"\n[!!!] DİKKAT: JPEG BOYUT MANİPÜLASYONU TESPİT EDİLDİ!")
                print(f"      Mevcut Görünür Boyut : {cur_w}x{cur_h}")
                print(f"      Tespit Edilen Gerçek : {target_w}x{target_h}")
                print(f"      Tespit Nedeni        : {reason}")
                print("[*] Gerçek boyutlar JPEG SOF marker'ına yazılarak görsel kurtarılıyor...")

                fixed_data = bytearray(data)
                fixed_data[sof_pos + 5 : sof_pos + 7] = struct.pack(">H", target_h)
                fixed_data[sof_pos + 7 : sof_pos + 9] = struct.pack(">H", target_w)

                fixed_path = os.path.join(self.output_dir, "fixed_dimensions.jpg")
                with open(fixed_path, "wb") as ff:
                    ff.write(fixed_data)

                print(f"[!!!] BAŞARILI! Düzeltilmiş JPEG oluşturuldu: {fixed_path}")
                print(f"      (Gizlenen alt/yan pikseller açığa çıkarıldı!)")

                with open(os.path.join(self.output_dir, "FOUND_FLAGS.txt"), "a", encoding="utf-8") as fl:
                    fl.write(f"\n--- JPEG Boyut Onarımı (SOF Marker) ---\n")
                    fl.write(f"Orijinal Kırpılmış Boyut: {cur_w}x{cur_h} -> Kurtarılan Gerçek Boyut: {target_w}x{target_h}\n")
                    fl.write(f"Tespit Nedeni: {reason}\n")
                    fl.write(f"Düzeltilmiş Dosya: {fixed_path}\n")

                # Kurtarılan görsel üzerinde otomatik OCR / metin taraması (Eğer tesseract varsa)
                try:
                    tesseract_bin = self._find_executable('tesseract')
                    if tesseract_bin:
                        ocr_res = subprocess.run([tesseract_bin, fixed_path, 'stdout', '--psm', '6'],
                                                 capture_output=True, text=True, errors="ignore")
                        if ocr_res.stdout:
                            self._search_flags_in_text("Kurtarılan Görsel (OCR)", ocr_res.stdout)
                except Exception:
                    pass
            else:
                print(f"[+] JPEG boyut doğrulaması tamamlandı ({cur_w}x{cur_h}).")
        except Exception as e:
            print(f"[-] JPEG boyut kontrol hatası: {e}")

    def check_and_carve_jpeg_anomalies(self) -> None:
        """JPEG dosyalarında Marker yapılarını, EOI sonrası gömülü (trailing overlay) verileri
        ve Scan segmentleri arasındaki bozuk/ekstra (extraneous) baytları tespit edip otomatik olarak çıkartır."""
        print("[+] JPEG Marker ve Anomali Analizi (Extraneous Bytes & Overlay) yapılıyor...")
        try:
            with open(self.file_path, "rb") as f:
                data = f.read()
        except Exception as e:
            print(f"[-] JPEG dosyası okunamadı: {e}")
            return

        file_size = len(data)
        if file_size < 4 or data[:2] != b'\xff\xd8':
            return

        extract_dir = os.path.join(self.output_dir, "extracted")
        if not os.path.exists(extract_dir):
            os.makedirs(extract_dir, exist_ok=True)

        # 1. EOI (0xFFD9) Kontrolü ve Trailing Overlay Carving
        eoi_pos = data.rfind(b'\xff\xd9')
        if eoi_pos != -1 and eoi_pos + 2 < file_size:
            overlay_size = file_size - (eoi_pos + 2)
            print(f"\n[!!!] DİKKAT: JPEG EOI (0xFFD9) sonrasında {overlay_size} byte gömülü ek veri (Trailing Overlay) tespit edildi!")
            overlay_data = data[eoi_pos + 2:]
            overlay_path = os.path.join(extract_dir, "jpeg_trailing_overlay.bin")
            with open(overlay_path, "wb") as of:
                of.write(overlay_data)
            self._inspect_extracted_files(extract_dir, "JPEG Trailing Overlay")

        # 2. JPEG Yorum (COM - 0xFFFE) Kontrolü
        p = 0
        while p < len(data) - 4:
            if data[p] == 0xFF and data[p+1] == 0xFE:
                c_len = (data[p+2] << 8) | data[p+3]
                com_bytes = data[p+4 : p+2+c_len]
                com_txt = com_bytes.decode('latin1', errors='replace')
                print(f"[!] JPEG Yorum (COM) segmenti tespit edildi: '{com_txt}'")
                self._search_flags_in_text("JPEG Comment", com_txt)
                p += 2 + c_len
            else:
                p += 1

        # 3. Extraneous Bytes Tespiti:
        # steghide_report.txt, djpeg veya dosya içindeki JPEG scan verilerinden otomatik ayıkla
        extraneous_matches = []
        steghide_rep_path = os.path.join(self.output_dir, "steghide_report.txt")
        if os.path.exists(steghide_rep_path):
            try:
                with open(steghide_rep_path, "r", encoding="utf-8", errors="ignore") as rf:
                    txt = rf.read()
                    for m in re.finditer(r'(\d+)\s+extraneous bytes before marker\s+(0x[0-9a-fA-F]+)', txt):
                        byte_count = int(m.group(1))
                        marker_hex = int(m.group(2), 16)
                        extraneous_matches.append((byte_count, marker_hex))
            except Exception:
                pass

        # Eğer djpeg sistemde varsa stderr kontrol et
        djpeg_bin = self._find_executable('djpeg')
        if not extraneous_matches and djpeg_bin:
            try:
                res = subprocess.run([djpeg_bin, '-v', '-v', self.file_path], capture_output=True, text=True, errors="replace")
                for m in re.finditer(r'(\d+)\s+extraneous bytes before marker\s+(0x[0-9a-fA-F]+)', res.stderr):
                    byte_count = int(m.group(1))
                    marker_hex = int(m.group(2), 16)
                    extraneous_matches.append((byte_count, marker_hex))
            except Exception:
                pass

        # Scan sonlandıran marker pozisyonlarını tespit et
        pos = 0
        scan_terminating_markers = []  # (marker_offset, marker_byte)
        while pos < len(data) - 1:
            if data[pos] == 0xFF:
                marker = data[pos + 1]
                if marker not in [0x00, 0xFF]:
                    if marker in [0xD8, 0xD9]:
                        pos += 2
                        continue
                    elif marker == 0xDA:  # SOS
                        if pos + 4 <= len(data):
                            length = (data[pos + 2] << 8) | data[pos + 3]
                            scan_start = pos + 2 + length
                            p = scan_start
                            while p < len(data) - 1:
                                if data[p] == 0xFF and data[p+1] not in [0x00, 0xFF] and not (0xD0 <= data[p+1] <= 0xD7):
                                    break
                                p += 1
                            if p < len(data) - 1:
                                scan_terminating_markers.append((p, data[p+1]))
                            pos = p
                            continue
                    else:
                        if pos + 4 <= len(data):
                            length = (data[pos + 2] << 8) | data[pos + 3]
                            pos += 2 + length
                            continue
            pos += 1

        # Bulunan extraneous verileri çıkart
        seen_extraneous = set()
        for byte_count, marker_hex in extraneous_matches:
            key = (byte_count, marker_hex)
            if key in seen_extraneous:
                continue
            seen_extraneous.add(key)
            
            # Sadece Scan sonlandıran doğru marker'ları hedefle
            for idx, m_byte in scan_terminating_markers:
                if m_byte == marker_hex and idx >= byte_count:
                    ext_bytes = data[idx - byte_count : idx]
                    core = ext_bytes.strip(b'\x00')
                    print(f"\n[!!!] BAŞARILI TESPİT: Marker 0x{marker_hex:02X} öncesinde {byte_count} byte gizli/bozuk veri (Extraneous Bytes) tespit edildi!")
                    print(f"      Konum: {idx - byte_count} - {idx} (0x{idx - byte_count:X} - 0x{idx:X})")
                    
                    out_name = f"jpeg_extraneous_{byte_count}b_offset_0x{idx - byte_count:X}_before_0x{marker_hex:02X}.bin"
                    out_path = os.path.join(extract_dir, out_name)
                    with open(out_path, "wb") as ef:
                        ef.write(ext_bytes)
                    print(f"      [+] Ham veri kaydedildi: {out_name}")
                    
                    if core and len(core) != len(ext_bytes):
                        core_name = f"jpeg_extraneous_{len(core)}b_core_offset_0x{idx - byte_count:X}.bin"
                        core_path = os.path.join(extract_dir, core_name)
                        with open(core_path, "wb") as cf:
                            cf.write(core)
                        print(f"      [+] Sıfırlardan arındırılmış çekirdek veri: {core_name}")

                    self._inspect_extracted_files(extract_dir, f"JPEG Extraneous (0x{marker_hex:02X})")
                    break

    def run_audio_analysis(self) -> None:
        """Ses dosyaları için Spektrogram grafiği ve özel analizler üretir."""
        print("[+] Ses Dosyası Analizi başlatılıyor...")
        base_name = os.path.splitext(os.path.basename(self.file_path))[0]
        ffmpeg_bin = self._find_executable('ffmpeg')
        if ffmpeg_bin:
            spec_path = os.path.join(self.output_dir, f"{base_name}_spectrogram.png")
            print("[+] Frekans Spektrogramı (Spectrogram) oluşturuluyor...")
            cmd = [
                ffmpeg_bin, '-y', '-i', self.file_path,
                '-lavfi', 'showspectrumpic=s=1400x700:legend=1:color=magma',
                spec_path
            ]
            subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if os.path.exists(spec_path):
                print(f"[+] Spektrogram başarıyla kaydedildi: {spec_path}")
                print("    (Ses içine çizilmiş gizli görsel mesajları bu dosyadan inceleyebilirsiniz.)")
        else:
            print("[-] ffmpeg sistemde bulunamadığı için spektrogram üretilemedi. (brew/apt install ffmpeg)")

    def run_exiftool(self) -> None:
        """ExifTool ile metadata analizi yapar."""
        print("[+] Metadata (Exif) Analizi yapılıyor...")
        try:
            result = subprocess.run(['exiftool', self.file_path], capture_output=True, text=True)
            report_path = os.path.join(self.output_dir, "exif_report.txt")
            with open(report_path, "w") as f:
                f.write(result.stdout)
            
            # Exif içinde flag ara
            self._search_flags_in_text("Metadata", result.stdout)
        except FileNotFoundError:
            print("[-] ExifTool sistemde bulunamadı!")

    def run_strings(self) -> None:
        """Dosya içindeki okunabilir gizli metinleri (Strings) çıkarır."""
        print("[+] Dosya içi gizli metin (Strings) analizi yapılıyor... (min 5 karakter)")
        try:
            # -n 8: Yalnızca ardışık 5 veya daha fazla okunabilir karakter içerenleri getir (Çöp veriyi azaltır)
            result = subprocess.run(['strings', '-n', '5', self.file_path], capture_output=True, text=True)
            report_path = os.path.join(self.output_dir, "strings_report.txt")
            with open(report_path, "w") as f:
                f.write(result.stdout)
            
            self._search_flags_in_text("Strings", result.stdout)
            
            # Gelişmiş Regex Kalıpları
            patterns = {
                'URL': re.compile(r'https?://(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(?:/[^\s]*)?'),
                'Email': re.compile(r'[a-zA-Z0-9_.+-]{2,}@[a-zA-Z0-9-]{2,}\.[a-zA-Z]{2,}'),
                'IP': re.compile(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'),
                'Base64_String': re.compile(r'\b(?:[A-Za-z0-9+/]{4}){5,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?\b'),
            }
            
            found_items = {k: set() for k in patterns}
            found_items['Meaningful_Sentence'] = set()
            found_items['Interesting_File_Or_Word'] = set()
            
            interesting_exts = ['.zip', '.rar', '.txt', '.png', '.jpg', '.pdf', '.kdbx']
            interesting_words = ['password', 'secret', 'admin', 'login', 'flag']

            xml_blocks = []
            current_xml = []
            in_xml = False

            for line in result.stdout.split('\n'):
                line = line.strip()
                if not line:
                    continue
                
                # XML bloğu tespit edildiyse, bu kısımlardaki sahte pozitifleri (Adobe namespace vb.) yoksayıyoruz
                if not in_xml and (line.startswith("<?xpacket") or line.startswith("<?xml") or "<x:xmpmeta" in line):
                    in_xml = True
                    current_xml.append(line)
                    continue
                    
                if in_xml:
                    current_xml.append(line)
                    if "<?xpacket end=" in line or "</x:xmpmeta>" in line or "</rdf:RDF>" in line or "</x:xmp" in line:
                        in_xml = False
                        xml_blocks.append("\n".join(current_xml))
                        current_xml = []
                    continue
                    
                # Regex ile yapısal veri ara
                for key, pattern in patterns.items():
                    for m in pattern.findall(line):
                        if key == 'Base64_String':
                            # JPEG Huffman table vb. ardışık dizilimleri (false positive) ele
                            if 'cdefghijstuvwxyz' in m.lower():
                                continue
                            # Sadece HEX formatındaki diziler genellikle Base64 değildir
                            if re.fullmatch(r'[0-9a-fA-F]+', m):
                                continue
                            # Padding yoksa ve tamamen harften ya da sayıdan oluşuyorsa muhtemelen rastgele string'tir
                            if not m.endswith('=') and (m.isalpha() or m.isdigit()):
                                continue
                        found_items[key].add(m)
                
                # Şüpheli dosya uzantıları / kelimeler
                line_lower = line.lower()
                if any(ext in line_lower for ext in interesting_exts) or any(w in line_lower for w in interesting_words):
                    found_items['Interesting_File_Or_Word'].add(line)
                
                # Sözlük bazlı anlamlı cümle tespiti
                if self.dictionary:
                    words = re.findall(r'[a-z]+', line_lower)
                    if words:
                        valid_words = [w for w in words if w in self.dictionary]
                        # En az 3 geçerli kelime varsa ve kelimelerin çoğu sözlükteyse
                        if len(valid_words) >= 3 and (len(valid_words) / len(words)) > 0.6:
                            found_items['Meaningful_Sentence'].add(line)

            # Çıkarılan XML varsa dosyaya kaydet
            if xml_blocks:
                xml_report_path = os.path.join(self.output_dir, "extracted_metadata.xml")
                with open(xml_report_path, "w") as xf:
                    for i, block in enumerate(xml_blocks):
                        xf.write(f"<!-- XML Block {i+1} -->\n{block}\n\n")
                print(f"[+] Strings: {len(xml_blocks)} adet devasa XML bloğu tespit edildi ve 'extracted_metadata.xml' dosyasına kaydedildi.")

            # Raporlama ve Alert
            has_found_items = any(items for items in found_items.values())
            if has_found_items:
                with open(os.path.join(self.output_dir, "FOUND_FLAGS.txt"), "a") as f:
                    for category, items in found_items.items():
                        if items:
                            sample = list(items)[:3]
                            print(f"[!] Strings Analizi: {len(items)} adet '{category}' bulundu! Örn: {sample}")
                            f.write(f"\n--- Strings ({category}) ---\n")
                            for item in items:
                                f.write(f"{item}\n")
                            
        except Exception as e:
            print(f"[-] Strings analizi hatası: {e}")

    def _search_flags_in_text(self, source: str, text: str) -> None:
        """Verilen metin içinde Regex ile Flag formatı arar."""
        flags = self.flag_pattern.findall(text)
        if flags:
            print(f"\n[!!!] {source} İÇİNDE MUHTEMEL BAYRAK BULUNDU: {flags}")
            with open(os.path.join(self.output_dir, "FOUND_FLAGS.txt"), "a") as f:
                f.write(f"Source: {source} -> {flags}\n")

    def extract_video_frames(self) -> List[str]:
        """Videoyu karelere böler."""
        print("[+] Video tespit edildi. Kareler çıkartılıyor...")
        frames_dir = os.path.join(self.output_dir, "frames")
        if not os.path.exists(frames_dir):
            os.makedirs(frames_dir)
            
        try:
            cmd = ['ffmpeg', '-i', self.file_path, os.path.join(frames_dir, 'frame_%04d.png')]
            subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return sorted([os.path.join(frames_dir, f) for f in os.listdir(frames_dir) if f.endswith('.png')])
        except FileNotFoundError:
            print("[-] FFmpeg sistemde bulunamadı! Video analizi atlanıyor. Lütfen 'brew install ffmpeg' ile kurun.")
            return []

    def run_visual_morse_analysis(self, image_path: str) -> None:
        """Görsellerin kenar veya satırlarında (1px çizgi halinde) gizlenmiş Mors kodlarını otomatik tespit edip çözer."""
        try:
            im = Image.open(image_path).convert('RGB')
        except Exception:
            return

        width, height = im.size
        morse_table = {
            '.-': 'A', '-...': 'B', '-.-.': 'C', '-..': 'D', '.': 'E',
            '..-.': 'F', '--.': 'G', '....': 'H', '..': 'I', '.---': 'J',
            '-.-': 'K', '.-..': 'L', '--': 'M', '-.': 'N', '---': 'O',
            '.--.': 'P', '--.-': 'Q', '.-.': 'R', '...': 'S', '-': 'T',
            '..-': 'U', '...-': 'V', '.--': 'W', '-..-': 'X', '-.--': 'Y',
            '--..': 'Z', '-----': '0', '.----': '1', '..---': '2',
            '...--': '3', '....-': '4', '.....': '5', '-....': '6',
            '--...': '7', '---..': '8', '----.': '9', '.-.-.-': '.',
            '--..--': ',', '...---...': 'SOS', '-.--.': '(', '-.--.-': ')',
            '-..-.': '/', '-....-': '-', '---...': ':', '.--.-.': '@'
        }

        # Taranacak satır ve sütunlar:
        lines_to_test = []
        for y in list(range(min(15, height))) + list(range(max(0, height - 15), height)):
            row = [1 if im.getpixel((x, y))[0] > 128 else 0 for x in range(width)]
            lines_to_test.append((f"Satır {y}", row))

        for x in list(range(min(15, width))) + list(range(max(0, width - 15), width)):
            col = [1 if im.getpixel((x, y))[0] > 128 else 0 for y in range(height)]
            lines_to_test.append((f"Sütun {x}", col))

        found_morse = []
        for label, bits in lines_to_test:
            runs = []
            cur = bits[0]
            l = 0
            for b in bits:
                if b == cur:
                    l += 1
                else:
                    runs.append((cur, l))
                    cur = b
                    l = 1
            runs.append((cur, l))

            if 6 <= len(runs) <= 250:
                for sig_val in [1, 0]:
                    sig_lens = [r_len for r_b, r_len in runs if r_b == sig_val]
                    if not sig_lens:
                        continue
                    unit = min(sig_lens)
                    if unit < 1:
                        continue

                    letters = []
                    curr_morse = ""
                    for r_b, r_len in runs:
                        u = round(r_len / unit)
                        if r_b == sig_val:
                            if u <= 2:
                                curr_morse += "."
                            else:
                                curr_morse += "-"
                        else:
                            if u >= 4:
                                if curr_morse:
                                    letters.append(curr_morse)
                                    curr_morse = ""
                                letters.append(" ")
                            elif u >= 2:
                                if curr_morse:
                                    letters.append(curr_morse)
                                    curr_morse = ""
                    if curr_morse:
                        letters.append(curr_morse)

                    words = []
                    curr_word = []
                    valid_chars = 0
                    total_chars = 0
                    for token in letters:
                        if token == " ":
                            if curr_word:
                                words.append("".join(curr_word))
                                curr_word = []
                        else:
                            total_chars += 1
                            ch = morse_table.get(token, None)
                            if ch:
                                valid_chars += 1
                                curr_word.append(ch)
                            else:
                                curr_word.append("?")
                    if curr_word:
                        words.append("".join(curr_word))

                    decoded_msg = " ".join(words).strip()
                    if total_chars >= 4 and (valid_chars / total_chars) >= 0.75:
                        cand = f"{label} (Polarite {sig_val}): {decoded_msg}"
                        if cand not in found_morse:
                            found_morse.append(cand)
                            print(f"\n[!!!] GÖRSEL MORS KODU TESPİT EDİLDİ! ({label}):")
                            print(f"      >>> {decoded_msg} <<<")
                            self._search_flags_in_text(f"Visual Morse ({label})", decoded_msg)

    def analyze_bit_planes(self, image_path: str) -> None:
        """Bir görselin R, G, B ve (varsa) Alpha kanallarının 0'dan 7'ye tüm bit düzlemlerini,
        Invert ve LSB/MSB yarılarını analiz edip grid ve ayrı dosyalar olarak kaydeder."""
        img = cv2.imread(image_path, cv2.IMREAD_UNCHANGED)
        if img is None:
            return

        if len(img.shape) == 3 and img.shape[2] == 4:
            b, g, r, a = cv2.split(img)
            channels = {'Red': r, 'Green': g, 'Blue': b, 'Alpha': a}
            if np.any(a != 255):
                print("[!] DİKKAT: Şeffaflık (Alpha) kanalı aktif ve pikseller homojen değil! (Gizli veri olasılığı yüksek)")
        elif len(img.shape) == 3 and img.shape[2] == 3:
            b, g, r = cv2.split(img)
            channels = {'Red': r, 'Green': g, 'Blue': b}
        elif len(img.shape) == 2:
            channels = {'Gray': img}
        else:
            return
        
        grid_rows = []
        height, width = img.shape[:2]
        header_height = 40
        base_name = os.path.splitext(os.path.basename(image_path))[0]

        for color_name, channel_matrix in channels.items():
            row_images = []
            if color_name == 'Red':
                color_bgr = (0, 0, 255)
            elif color_name == 'Green':
                color_bgr = (0, 255, 0)
            elif color_name == 'Blue':
                color_bgr = (255, 0, 0)
            elif color_name == 'Alpha':
                color_bgr = (255, 255, 255)
            else:
                color_bgr = (200, 200, 200)
            
            variations = []
            
            # 0'dan 7'ye TÜM BİTLER (Tam Stegsolve Desteği)
            for bit in range(8):
                bit_plane = ((channel_matrix >> bit) & 1) * 255
                variations.append((f"{color_name} Bit {bit}", bit_plane))
                
            # Ters Çevrilmiş (Invert) Düzlem
            variations.append((f"{color_name} Invert", 255 - channel_matrix))

            # LSB Half (Alt 4 bit)
            lsb_half = (channel_matrix & 0x0F) * 16
            variations.append((f"{color_name} LSB Half", lsb_half))
            
            # MSB Half (Üst 4 bit)
            msb_half = (channel_matrix & 0xF0)
            variations.append((f"{color_name} MSB Half", msb_half))
            
            for title, img_data in variations:
                if self.save_separate:
                    safe_title = title.replace(' ', '_')
                    sep_save_path = os.path.join(self.bit_planes_dir, f"{base_name}_{safe_title}.png")
                    cv2.imwrite(sep_save_path, img_data)

                # 3 kanallı BGR'a çevir
                colored_plane = cv2.cvtColor(img_data, cv2.COLOR_GRAY2BGR)
                
                # Etiket için siyah başlık alanı oluştur
                header = np.zeros((header_height, width, 3), dtype=np.uint8)
                cv2.putText(header, title, (10, 28), cv2.FONT_HERSHEY_SIMPLEX, 1, color_bgr, 2)
                
                # Başlık ve görseli dikey olarak birleştir
                panel = np.vstack((header, colored_plane))
                row_images.append(panel)
            
            # Satırı yatay olarak birleştir
            row_concat = np.hstack(row_images)
            grid_rows.append(row_concat)
            
        # Tüm satırları dikey olarak birleştir
        final_grid = np.vstack(grid_rows)
        
        # Grid'i tek dosya olarak kaydet
        save_path = os.path.join(self.bit_planes_dir, f"{base_name}_BitPlanes_Grid.png")
        cv2.imwrite(save_path, final_grid)

    def run_binwalk(self) -> None:
        """Binwalk ile dosya içine gizlenmiş başka dosyaları (embedded files) tespit eder."""
        print("[+] Binwalk ile gömülü dosya analizi yapılıyor...")
        try:
            result = subprocess.run(['binwalk', self.file_path], capture_output=True, text=True)
            report_path = os.path.join(self.output_dir, "binwalk_report.txt")
            with open(report_path, "w") as f:
                f.write(result.stdout)
            
            self._search_flags_in_text("Binwalk", result.stdout)
            
            lines = result.stdout.split('\n')
            signatures = []
            
            for line in lines:
                # Binwalk çıktıları ondalık (decimal) offset ile başlar. Örn: '0             0x0             JPEG...'
                if re.match(r'^\d+\s+0x[0-9A-Fa-f]+\s+', line):
                    signatures.append(line.strip())
            
            if len(signatures) > 1:
                print(f"[!!!] DİKKAT: Binwalk dosya içinde BEKLENMEYEN VERİ FORMATLARI tespit etti!")
                print(f"      Ana dosya imzası haricinde {len(signatures)-1} adet farklı gömülü yapı bulundu.")
                print("      Bulunan imzalar:")
                for sig in signatures:
                    print(f"      -> {sig}")
                    
                # Dosyaları çıkart
                extract_dir = os.path.join(self.output_dir, "extracted")
                print(f"[+] Gömülü dosyalar '{extract_dir}' klasörüne çıkartılıyor...")
                subprocess.run(['binwalk', '-e', '-C', extract_dir, self.file_path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                print(f"[+] Çıkartma işlemi tamamlandı. Çıkan dosyaları '{extract_dir}' içinde inceleyebilirsiniz.")
                
            elif len(signatures) == 1:
                print("[+] Binwalk: Gömülü ek veri bulunamadı (Sadece orijinal dosya imzası).")
            else:
                print("[-] Binwalk: Herhangi bir geçerli imza tespit edilemedi.")
                    
        except FileNotFoundError:
            print("[-] Binwalk sistemde bulunamadı! 'brew install binwalk' ile kurabilirsiniz.")

    def run_zsteg(self) -> None:
        """zsteg ile PNG/BMP LSB/MSB steganografi analizi yapar."""
        print("[+] zsteg ile LSB/MSB/Kanal Steganografi Analizi yapılıyor...")
        zsteg_bin = self._find_executable('zsteg')
        if not zsteg_bin:
            print("[-] zsteg sistemde bulunamadı!")
            print("    Kurulum için (Terminal): 'gem install zsteg'")
            return

        try:
            cmd = [zsteg_bin]
            if self.zsteg_all:
                cmd.append("-a")
            cmd.append(self.file_path)

            result = subprocess.run(cmd, capture_output=True, text=True, errors="replace")
            output = result.stdout
            
            report_path = os.path.join(self.output_dir, "zsteg_report.txt")
            with open(report_path, "w", encoding="utf-8") as f:
                f.write(output)
            
            # zsteg çıktısında bayrak (flag) ara
            self._search_flags_in_text("zsteg", output)

            # Çıktı satırlarını incele: metin veya dosya barındıran kritik satırları öne çıkar
            interesting_lines = []
            extract_candidates = []
            for line in output.splitlines():
                line_str = line.strip()
                if not line_str:
                    continue
                if '.. text:' in line_str or '.. file:' in line_str or self.flag_pattern.search(line_str):
                    interesting_lines.append(line_str)
                    match = re.match(r'^([a-zA-Z0-9,]+)\s+\.\.', line_str)
                    if match:
                        extract_candidates.append((match.group(1), line_str))

            if interesting_lines:
                print(f"[!] zsteg: {len(interesting_lines)} adet dikkat çekici steganografi kanalı tespit edildi!")
                for item in interesting_lines[:5]:
                    print(f"      -> {item}")
                if len(interesting_lines) > 5:
                    print(f"      ... (ve {len(interesting_lines) - 5} adet daha. Detaylar: zsteg_report.txt)")

                with open(os.path.join(self.output_dir, "FOUND_FLAGS.txt"), "a", encoding="utf-8") as f:
                    f.write("\n--- zsteg Bulguları ---\n")
                    for item in interesting_lines:
                        f.write(f"{item}\n")

                # Payload çıkartma (zsteg -E)
                extracted_dir = os.path.join(self.output_dir, "zsteg_extracted")
                for channel, desc in extract_candidates[:3]:
                    if self.flag_pattern.search(desc) or any(ft in desc for ft in ['Zip', 'ELF', 'PNG', 'JPEG', 'PDF', 'gzip', 'tar', 'text']):
                        if not os.path.exists(extracted_dir):
                            os.makedirs(extracted_dir)
                        safe_ch = channel.replace(',', '_')
                        out_file = os.path.join(extracted_dir, f"payload_{safe_ch}.bin")
                        ext_res = subprocess.run([zsteg_bin, '-E', channel, self.file_path], capture_output=True)
                        if ext_res.returncode == 0 and ext_res.stdout:
                            with open(out_file, "wb") as pf:
                                pf.write(ext_res.stdout)
                            print(f"[+] zsteg: '{channel}' kanalı ham verisi çıkarıldı: {out_file}")
            else:
                print("[+] zsteg: Belirgin bir gizli metin veya dosya imzası yakalanamadı.")

        except Exception as e:
            print(f"[-] zsteg analizi sırasında hata oluştu: {e}")

    def _inspect_extracted_files(self, extract_dir: str, source_tag: str) -> None:
        """Çıkartılan dosyaları listeler, boyutlarını gösterir, önizlemelerini ve içeriklerini kaydeder."""
        if not os.path.exists(extract_dir):
            return
        files = [os.path.join(extract_dir, f) for f in os.listdir(extract_dir) if os.path.isfile(os.path.join(extract_dir, f))]
        if not files:
            return
        
        print(f"[+] Çıkarılan Dosyalar ({source_tag}):")
        with open(os.path.join(self.output_dir, "FOUND_FLAGS.txt"), "a", encoding="utf-8") as flag_file:
            flag_file.write(f"\n--- {source_tag} Çıkarılan Dosyalar ---\n")
            for fpath in files:
                fname = os.path.basename(fpath)
                fsize = os.path.getsize(fpath)
                rel_path = os.path.relpath(fpath, self.output_dir)
                print(f"      -> {fname} ({fsize} byte)")
                flag_file.write(f"Dosya: {fname} ({fsize} byte)\n")
                
                content_text = None
                clean_lines = []
                try:
                    with open(fpath, "rb") as f:
                        raw_data = f.read(65536)
                    try:
                        content_text = raw_data.decode('utf-8')
                    except UnicodeDecodeError:
                        try:
                            content_text = raw_data.decode('latin-1')
                        except Exception:
                            content_text = None

                    if content_text:
                        self._search_flags_in_text(f"{source_tag} -> {fname}", content_text)
                        clean_lines = [l.strip() for l in content_text.splitlines() if l.strip()]
                        if clean_lines:
                            preview = clean_lines[0][:150]
                            print(f"         İçerik: {preview}")
                            flag_file.write(f"   İçerik: {preview}\n")
                            if len(clean_lines) <= 20 and fsize <= 4096:
                                flag_file.write("   Dosya İçeriği:\n")
                                for cl in clean_lines:
                                    flag_file.write(f"      {cl}\n")

                    existing_entry = next((item for item in self.extracted_files_meta if item['path'] == fpath), None)
                    if not existing_entry:
                        self.extracted_files_meta.append({
                            'filename': fname,
                            'path': fpath,
                            'relpath': rel_path,
                            'size': fsize,
                            'source': source_tag,
                            'is_text': bool(content_text),
                            'content': content_text[:8192] if content_text else None,
                            'preview': clean_lines[0][:150] if clean_lines else None,
                            'decoded_info': None
                        })
                except Exception:
                    pass

    def run_steghide(self) -> None:
        """Steghide ile JPEG, BMP ve WAV/AU dosyalarında gömülü veri analizi ve çıkartma yapar."""
        print("[+] Steghide ile gömülü veri analizi yapılıyor...")
        steghide_bin = self._find_executable('steghide')
        if not steghide_bin:
            print("[-] steghide sistemde bulunamadı!")
            print("    Kurulum için (Kali / Debian / Ubuntu): 'sudo apt install -y steghide'")
            print("    macOS için: 'sudo port install steghide' veya Kali Linux üzerinde çalıştırabilirsiniz.")
            return

        extract_dir = os.path.join(self.output_dir, "steghide_extracted")
        if not os.path.exists(extract_dir):
            os.makedirs(extract_dir)

        report_path = os.path.join(self.output_dir, "steghide_report.txt")
        reports = []

        passwords_to_try = []
        if self.passphrase is not None:
            passwords_to_try.append(self.passphrase)
        if "" not in passwords_to_try:
            passwords_to_try.append("")

        # 🧠 Akıllı Parola Avcısı: Dosya adı, Exif etiketleri ve popüler CTF parolaları
        base_no_ext = os.path.splitext(os.path.basename(self.file_path))[0]
        words = re.findall(r'[A-Za-z0-9]+', base_no_ext)
        candidates = [base_no_ext, base_no_ext.lower(), base_no_ext.upper()]
        for w in words:
            if len(w) >= 3:
                candidates.extend([w, w.lower(), w.upper(), w.capitalize()])
        if len(words) > 1:
            joined = "".join(words)
            candidates.extend([joined, joined.lower(), joined.upper(), joined.capitalize()])

        # Exif metadata'dan kelimeler topla
        exif_report_path = os.path.join(self.output_dir, "exif_report.txt")
        if os.path.exists(exif_report_path):
            try:
                with open(exif_report_path, "r", encoding="utf-8", errors="ignore") as ef:
                    for line in ef:
                        if ":" in line:
                            val = line.split(":", 1)[1].strip()
                            if 3 <= len(val) <= 40:
                                candidates.append(val)
                                for vw in re.findall(r'[A-Za-z0-9]+', val):
                                    if len(vw) >= 3:
                                        candidates.extend([vw, vw.lower(), vw.upper(), vw.capitalize()])
            except Exception:
                pass

        # Standart CTF parolaları
        common_ctf = ["password", "123456", "admin", "stego", "flag", "ctf", "secret", "hidden", "root", "toor"]
        candidates.extend(common_ctf)

        for c in candidates:
            if c and c not in passwords_to_try:
                passwords_to_try.append(c)

        abs_file_path = os.path.abspath(self.file_path)
        stegseek_bin = self._find_executable('stegseek')

        # Otomatik rockyou.txt tespiti (Kali / Ubuntu / Parrot)
        wordlist_to_use = self.wordlist
        if not wordlist_to_use:
            for common_wl in ["/usr/share/wordlists/rockyou.txt", "/usr/share/wordlists/rockyou.txt.gz",
                              "/opt/wordlists/rockyou.txt", os.path.expanduser("~/wordlists/rockyou.txt")]:
                if os.path.exists(common_wl):
                    wordlist_to_use = common_wl
                    break

        if wordlist_to_use and os.path.exists(wordlist_to_use) and stegseek_bin:
            print(f"[+] stegseek tespit edildi! '{wordlist_to_use}' sözlüğü ile hızlı parola denemesi başlatılıyor...")
            seek_res = subprocess.run([stegseek_bin, abs_file_path, wordlist_to_use, '-xf', os.path.join(extract_dir, 'stegseek_extracted.bin')],
                                      capture_output=True, text=True, errors="replace")
            if seek_res.returncode == 0:
                print(f"[!!!] STEGSEEK BAŞARILI! Parola tespit edildi ve dosya çıkarıldı!")
                print(seek_res.stdout.strip())
                reports.append("=== Stegseek Sonucu ===")
                reports.append(seek_res.stdout)
                self._search_flags_in_text("Stegseek", seek_res.stdout)
                self._inspect_extracted_files(extract_dir, "Stegseek")
                with open(report_path, "w", encoding="utf-8") as f:
                    f.write("\n".join(reports))
                return
        elif self.wordlist and os.path.exists(self.wordlist):
            try:
                with open(self.wordlist, "r", encoding="utf-8", errors="ignore") as wf:
                    for idx, line in enumerate(wf):
                        w = line.strip()
                        if w and w not in passwords_to_try:
                            passwords_to_try.append(w)
                        if idx >= 50:
                            break
                print(f"[*] Wordlist'ten ilk {len(passwords_to_try)} parola deneniyor...")
            except Exception as e:
                print(f"[-] Wordlist okuma hatası: {e}")

        extracted_any = False
        print(f"[*] Steghide için toplam {len(passwords_to_try)} adet aday parola deneniyor...")
        for p in passwords_to_try:
            pass_label = "BOŞ (\"\")" if p == "" else f"'{p}'"
            try:
                info_cmd = [steghide_bin, 'info', abs_file_path, '-p', p]
                info_res = subprocess.run(info_cmd, capture_output=True, text=True, errors="replace")
                
                extract_cmd = [steghide_bin, 'extract', '-sf', abs_file_path, '-p', p, '-f']
                ext_res = subprocess.run(extract_cmd, cwd=extract_dir, capture_output=True, text=True, errors="replace")
                
                combined_out = f"Parola: {pass_label}\nInfo:\n{info_res.stdout}\n{info_res.stderr}\nExtract:\n{ext_res.stdout}\n{ext_res.stderr}"
                reports.append(combined_out)

                # Extraneous bytes uyarısı varsa anında tespit et
                for stderr_out in [info_res.stderr, ext_res.stderr]:
                    if "extraneous bytes before marker" in stderr_out:
                        m = re.search(r'(\d+)\s+extraneous bytes before marker\s+(0x[0-9a-fA-F]+)', stderr_out)
                        if m:
                            print(f"\n[!] Steghide uyarısı: {m.group(1)} extraneous bytes before marker {m.group(2)}!")

                if ext_res.returncode == 0 or "wrote extracted data to" in ext_res.stdout.lower() or "wrote extracted data to" in ext_res.stderr.lower():
                    print(f"\n[!!!] STEGHIDE BAŞARILI! Gömülü veri başarıyla çıkartıldı! (Kullanılan Parola: {pass_label})")
                    extracted_any = True
                    self._search_flags_in_text("Steghide", ext_res.stdout + " " + info_res.stdout)
                    self._inspect_extracted_files(extract_dir, f"Steghide (Parola: {pass_label})")
                    break

            except Exception as e:
                reports.append(f"Hata ({pass_label}): {e}")

        if not extracted_any:
            print("[-] Steghide: Belirtilen/varsayılan parolalar ile gömülü veri çıkarılamadı.")
            print("    İpucu: Eğer parola korumalıysa '--passphrase <parola>' veya '--wordlist <dosya>' parametrelerini kullanabilirsiniz.")

        with open(report_path, "w", encoding="utf-8") as f:
            f.write("\n\n".join(reports))

    def _is_meaningful_text(self, txt: str) -> bool:
        """Metnin okunabilir, anlamlı bir metin veya URL olup olmadığını denetler (gürültüyü eler)."""
        if not txt or len(txt.strip()) < 4:
            return False
        printable_chars = set(string.printable)
        total_len = len(txt)
        printable_count = sum(1 for c in txt if c in printable_chars and c not in '\x0b\x0c')
        if printable_count / total_len < 0.90:
            return False
        alnum_count = sum(1 for c in txt if c.isalnum())
        if alnum_count < 3:
            return False
        if len(set(txt)) <= 2 and len(txt) > 8:
            return False
        return True

    def run_decode_wizard(self) -> None:
        """Strings, metadata ve çıkartılan tüm dosyalar üzerinde otomatik Base64, Base32, Hex, ROT13, URL ve Ters Çevirme dener."""
        print("[+] Otomatik Decode Sihirbazı (Mini CyberChef) çalıştırılıyor...")
        
        candidates: List[tuple] = []  # (source, string_candidate)
        seen_candidates: Set[str] = set()

        def add_candidate(src: str, text: str):
            t = text.strip()
            if 4 <= len(t) <= 10000 and t not in seen_candidates:
                seen_candidates.add(t)
                candidates.append((src, t))

        # 1. Çıkartılan tüm dosyaları tara (steghide_extracted, zsteg_extracted vb.)
        for ext_meta in self.extracted_files_meta:
            source = f"{ext_meta['source']} ({ext_meta['filename']})"
            if ext_meta.get('content'):
                cnt = ext_meta['content'].strip()
                add_candidate(source, cnt)
                for line in cnt.splitlines():
                    add_candidate(source, line)
                # Regex ile gömülü Base64 ve Hex bloklarını bul
                for b64_match in re.findall(r'[A-Za-z0-9+/]{12,}={0,2}', cnt):
                    add_candidate(source, b64_match)
                for hex_match in re.findall(r'[0-9a-fA-F]{16,}', cnt):
                    add_candidate(source, hex_match)

        # 2. strings_report.txt tara
        strings_report = os.path.join(self.output_dir, "strings_report.txt")
        if os.path.exists(strings_report):
            try:
                with open(strings_report, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        w = line.strip()
                        if 6 <= len(w) <= 2000 and " " not in w:
                            add_candidate("strings", w)
            except Exception:
                pass

        # 3. Trailing Data (.bin) tara
        trailing_file = os.path.join(self.output_dir, "png_trailing_data.bin")
        if os.path.exists(trailing_file):
            try:
                with open(trailing_file, "rb") as tf:
                    t_data = tf.read(65536)
                    for match in re.findall(b'[ -~]{6,}', t_data):
                        add_candidate("png_trailing_data", match.decode('ascii', errors='ignore'))
            except Exception:
                pass

        decoded_findings = []
        decoded_files_dir = os.path.join(self.output_dir, "decoded_files")

        url_regex = re.compile(r'https?://[^\s<>\"\'\)]+|ftp://[^\s<>\"\'\)]+')
        b64_pattern = re.compile(r'^[A-Za-z0-9+/]{4,}={0,2}$')
        b32_pattern = re.compile(r'^[A-Z2-7]{8,}={0,6}$', re.IGNORECASE)
        hex_pattern = re.compile(r'^[0-9a-fA-F]{6,}$')
        binary_pattern = re.compile(r'^(?:[01]{8}\s*)+$')

        def record_finding(source: str, method: str, original: str, raw_bytes: bytes, decoded_text: Optional[str]) -> bool:
            # 1. Dosya Başlığı / Magic Byte Kontrolü (Carve)
            magic_headers = [
                (b'PK\x03\x04', '.zip'),
                (b'\x89PNG\r\n\x1a\n', '.png'),
                (b'\xff\xd8\xff', '.jpg'),
                (b'%PDF-', '.pdf'),
                (b'\x7fELF', '.elf'),
                (b'\x1f\x8b', '.tar.gz'),
                (b'7z\xbc\xaf\x27\x1c', '.7z'),
                (b'Rar!\x1a\x07', '.rar')
            ]
            if raw_bytes:
                for magic, ext in magic_headers:
                    if raw_bytes.startswith(magic):
                        if not os.path.exists(decoded_files_dir):
                            os.makedirs(decoded_files_dir)
                        out_f = os.path.join(decoded_files_dir, f"carved_{method.lower()}_{abs(hash(original)) % 10000}{ext}")
                        with open(out_f, "wb") as cf:
                            cf.write(raw_bytes)
                        rel_out = os.path.relpath(out_f, self.output_dir)
                        finding = {
                            'method': method,
                            'source': source,
                            'original': original,
                            'decoded': f"Gömülü Dosya Çıkarıldı ({ext}): {os.path.basename(out_f)}",
                            'carved_file': out_f,
                            'rel_carved': rel_out,
                            'flags': [],
                            'urls': [],
                            'finding_type': 'Dosya'
                        }
                        decoded_findings.append(finding)
                        print(f"[!] Decode Sihirbazı ({method}) dosya çıkardı: {out_f}")
                        return True

            # 2. Metin / URL / Flag Değerlendirmesi
            if decoded_text:
                txt = decoded_text.strip()
                if txt == original.strip():
                    return False
                
                flags = self.flag_pattern.findall(txt)
                urls = url_regex.findall(txt)
                is_meaningful = self._is_meaningful_text(txt)

                if flags or urls or is_meaningful:
                    finding_type = "Flag" if flags else ("URL" if urls else "Metin")
                    finding = {
                        'method': method,
                        'source': source,
                        'original': original,
                        'decoded': txt,
                        'carved_file': None,
                        'flags': flags,
                        'urls': urls,
                        'finding_type': finding_type
                    }
                    decoded_findings.append(finding)
                    
                    if flags:
                        self._search_flags_in_text(f"Decode Sihirbazı ({method})", txt)

                    for meta in self.extracted_files_meta:
                        if meta['filename'] in source or meta['source'] in source:
                            if not meta.get('decoded_info'):
                                meta['decoded_info'] = f"{method} -> {txt}"

                    return True
            return False

        def is_ignored_schema(s: str) -> bool:
            s_low = s.lower()
            return any(ign in s_low for ign in ["adobe.com", "w3.org", "purl.org", "attribution.com", "iptc.org", "schema.org", "xap/1.0"])

        for source, item in candidates:
            if is_ignored_schema(item):
                continue

            # A. Base64 Denemesi
            if b64_pattern.match(item) and len(item) >= 4:
                padded = item + '=' * ((4 - len(item) % 4) % 4)
                try:
                    raw = base64.b64decode(padded)
                    txt = raw.decode('utf-8', errors='ignore')
                    if record_finding(source, "Base64", item, raw, txt):
                        # Çok katmanlı Base64 kontrolü
                        if b64_pattern.match(txt) and len(txt) >= 8:
                            try:
                                raw2 = base64.b64decode(txt + '=' * ((4 - len(txt) % 4) % 4))
                                txt2 = raw2.decode('utf-8', errors='ignore')
                                record_finding(f"{source} (Katman 2)", "Base64->Base64", txt, raw2, txt2)
                            except Exception:
                                pass
                except Exception:
                    pass

            # B. Base32 Denemesi
            if b32_pattern.match(item) and len(item) >= 8:
                try:
                    padded_b32 = item.upper() + '=' * ((8 - len(item) % 8) % 8)
                    raw_b32 = base64.b32decode(padded_b32)
                    txt_b32 = raw_b32.decode('utf-8', errors='ignore')
                    record_finding(source, "Base32", item, raw_b32, txt_b32)
                except Exception:
                    pass

            # C. Hex Denemesi
            if hex_pattern.match(item) and len(item) % 2 == 0 and len(item) >= 6:
                try:
                    raw_hex = bytes.fromhex(item)
                    txt_hex = raw_hex.decode('utf-8', errors='ignore')
                    record_finding(source, "Hex", item, raw_hex, txt_hex)
                except Exception:
                    pass

            # D. İkili (Binary ASCII: 01000001...) Denemesi
            if binary_pattern.match(item) and len(item.replace(" ", "")) >= 8:
                try:
                    clean_bin = item.replace(" ", "")
                    if len(clean_bin) % 8 == 0:
                        raw_bin = bytes(int(clean_bin[i:i+8], 2) for i in range(0, len(clean_bin), 8))
                        txt_bin = raw_bin.decode('utf-8', errors='ignore')
                        record_finding(source, "Binary", item, raw_bin, txt_bin)
                except Exception:
                    pass

            # E. URL-Encoding (%41%42...)
            if "%" in item:
                try:
                    unquoted = urllib.parse.unquote(item)
                    if unquoted != item and not is_ignored_schema(unquoted):
                        record_finding(source, "URL-Decode", item, b"", unquoted)
                except Exception:
                    pass

            # F. ROT13 & Reverse (Yalnızca potansiyel flag, anahtar veya şifreli metin içerenler)
            if ("{" in item and "}" in item) or any(k in item.lower() for k in ["ctf", "flag", "key", "pass"]):
                try:
                    rot13 = codecs.decode(item, 'rot_13')
                    rot_flags = self.flag_pattern.findall(rot13)
                    if rot_flags or any(kw in rot13.lower() for kw in ["flag", "ctf", "stm", "password", "secret", "token", "http://", "https://"]):
                        record_finding(source, "ROT13", item, b"", rot13)
                except Exception:
                    pass

                try:
                    rev = item[::-1]
                    rev_flags = self.flag_pattern.findall(rev)
                    if rev_flags or any(kw in rev.lower() for kw in ["flag", "ctf", "stm", "password", "secret", "token", "http://", "https://"]):
                        record_finding(source, "Reverse", item, b"", rev)
                except Exception:
                    pass

        self.decoded_findings = decoded_findings

        if decoded_findings:
            print(f"\n[!!!] Decode Sihirbazı: {len(decoded_findings)} adet veri başarıyla çözümlendi!")
            with open(os.path.join(self.output_dir, "FOUND_FLAGS.txt"), "a", encoding="utf-8") as fl_f:
                fl_f.write("\n--- Decode Sihirbazı (CyberChef) Bulguları ---\n")
                for df in decoded_findings:
                    m = df['method']
                    src = df['source']
                    orig = df['original']
                    dec = df['decoded']
                    ftype = df['finding_type']
                    print(f"      -> [{m}] ({src}):")
                    print(f"         Orijinal : {orig[:80]}")
                    print(f"         Çözümlenen ({ftype}): {dec[:100]}")
                    fl_f.write(f"[{m}] Kaynak: {src}\n")
                    fl_f.write(f"Orijinal : {orig}\n")
                    fl_f.write(f"Çözümlenen ({ftype}): {dec}\n\n")

            with open(os.path.join(self.output_dir, "cyberchef_report.txt"), "w", encoding="utf-8") as cf_f:
                for df in decoded_findings:
                    cf_f.write(f"=== {df['method']} Analizi ({df['source']}) ===\n")
                    cf_f.write(f"Orijinal Metin   : {df['original']}\n")
                    cf_f.write(f"Bulgu Tipi       : {df['finding_type']}\n")
                    cf_f.write(f"Çözümlenen Sonuç : {df['decoded']}\n\n")
        else:
            print("[+] Decode Sihirbazı: Belirgin Base64/Hex/ROT13 bayrağı veya anlamlı metin bulunamadı.")

    def generate_html_report(self) -> None:
        """Sıfır bağımlılıklı, karanlık temalı, interaktif ve modern CTF web raporu (index.html) oluşturur."""
        print("[+] İnteraktif HTML Raporu (Dashboard) oluşturuluyor...")
        
        # 1. Dosya bilgileri
        base_name = os.path.splitext(os.path.basename(self.file_path))[0]
        file_name = os.path.basename(self.file_path)
        try:
            sz = os.path.getsize(self.file_path)
            size_fmt = f"{sz / (1024*1024):.2f} MB ({sz:,} B)" if sz > 1024*1024 else f"{sz / 1024:.2f} KB ({sz:,} B)"
        except Exception:
            size_fmt = "Bilinmiyor"

        # 2. Bayraklar
        found_flags_file = os.path.join(self.output_dir, "FOUND_FLAGS.txt")
        flags = []
        raw_flags_text = ""
        if os.path.exists(found_flags_file):
            with open(found_flags_file, "r", encoding="utf-8", errors="ignore") as f:
                raw_flags_text = f.read().replace('\x00', '')
            for fl in self.flag_pattern.findall(raw_flags_text):
                if fl not in flags:
                    flags.append(fl)

        # 3. Bit Düzlemleri Görselleri
        grid_img = None
        bit_plane_files = []
        if os.path.exists(self.bit_planes_dir):
            for f in sorted(os.listdir(self.bit_planes_dir)):
                if f.endswith('.png'):
                    rel = f"bit_planes/{f}"
                    if "BitPlanes_Grid" in f:
                        grid_img = rel
                    else:
                        bit_plane_files.append((f.replace(f"{base_name}_", "").replace(".png", "").replace("_", " "), rel))

        # 4. Spektrogram Görseli
        spec_img = None
        cand_spec = os.path.join(self.output_dir, f"{base_name}_spectrogram.png")
        if os.path.exists(cand_spec):
            spec_img = f"{base_name}_spectrogram.png"

        # 5. Düzeltilmiş Görsel (PNG veya JPEG)
        fixed_img = None
        cand_fixed_jpg = os.path.join(self.output_dir, "fixed_dimensions.jpg")
        cand_fixed_png = os.path.join(self.output_dir, "fixed_dimensions.png")
        if os.path.exists(cand_fixed_jpg):
            fixed_img = ("fixed_dimensions.jpg", "JPEG (SOF Yükseklik/Genişlik Onarımı)")
        elif os.path.exists(cand_fixed_png):
            fixed_img = ("fixed_dimensions.png", "PNG (IHDR CRC Onarımı)")

        # Galeri Görselleri Listesi (Modal Gezintisi ve Zoom için)
        gallery_images = []
        if grid_img:
            gallery_images.append({'title': 'Bit Düzlemleri Izgarası (Grid)', 'src': grid_img})
        if fixed_img:
            gallery_images.append({'title': f'Düzeltilmiş Görsel ({fixed_img[1]})', 'src': fixed_img[0]})
        if spec_img:
            gallery_images.append({'title': 'Frekans Spektrogramı (Spectrogram)', 'src': spec_img})
        for label, rel_p in bit_plane_files:
            gallery_images.append({'title': label, 'src': rel_p})
        gallery_json = json.dumps(gallery_images)

        # 6. Rapor Metinleri
        report_files = [
            ("cyberchef_report.txt", "🧠 Decode Sihirbazı"),
            ("zsteg_report.txt", "🔍 zsteg Analizi"),
            ("steghide_report.txt", "🔒 Steghide Analizi"),
            ("binwalk_report.txt", "📦 Binwalk Gömülü Veri"),
            ("exif_report.txt", "🏷️ ExifTool Metadata"),
            ("strings_report.txt", "📜 Strings Raporu"),
        ]
        reports_data = []
        for rf, title in report_files:
            rp = os.path.join(self.output_dir, rf)
            if os.path.exists(rp):
                try:
                    with open(rp, "r", encoding="utf-8", errors="ignore") as rfh:
                        c = rfh.read(150000).replace('\x00', '')
                        reports_data.append((rf, title, html.escape(c)))
                except Exception:
                    pass

        # 7. Çıkartılan Dosyalar
        extracted_files = []
        for sdir in ["steghide_extracted", "zsteg_extracted", "extracted", "decoded_files"]:
            full_sdir = os.path.join(self.output_dir, sdir)
            if os.path.exists(full_sdir):
                for root, _, files in os.walk(full_sdir):
                    for f in files:
                        full_fp = os.path.join(root, f)
                        rel_fp = os.path.relpath(full_fp, self.output_dir)
                        fsize = os.path.getsize(full_fp)
                        extracted_files.append((f, rel_fp, fsize, sdir))

        # HTML Şablonunu Üret
        html_content = f"""<!DOCTYPE html>
<html lang="tr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Stegsolve CTF Raporu - {html.escape(file_name)}</title>
<style>
  :root {{
    --bg-color: #0a0e17;
    --card-bg: #111827;
    --card-border: #1f2937;
    --accent-green: #00ff88;
    --accent-cyan: #38bdf8;
    --accent-amber: #f59e0b;
    --accent-red: #ef4444;
    --text-main: #f3f4f6;
    --text-muted: #9ca3af;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    background-color: var(--bg-color);
    color: var(--text-main);
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    line-height: 1.6;
    padding: 24px;
  }}
  .container {{ max-width: 1400px; margin: 0 auto; }}
  header {{
    background: var(--card-bg); border: 1px solid var(--card-border);
    border-radius: 12px; padding: 22px 28px; margin-bottom: 24px;
    box-shadow: 0 4px 20px rgba(0,0,0,0.5);
  }}
  .header-top {{ display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 12px; }}
  .header-title h1 {{ font-size: 22px; font-weight: 700; color: #fff; display: flex; align-items: center; gap: 10px; }}
  .badge {{ background: rgba(0,255,136,0.15); color: var(--accent-green); font-size: 12px; padding: 4px 10px; border-radius: 20px; border: 1px solid var(--accent-green); }}
  .meta-grid {{
    display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 10px;
    margin-top: 16px; font-size: 13px; color: var(--text-muted);
  }}
  .meta-item {{ background: rgba(255,255,255,0.02); padding: 8px 12px; border-radius: 6px; border: 1px solid var(--card-border); }}
  .meta-item strong {{ color: var(--accent-cyan); }}

  /* Bayrak Kartı */
  .flag-banner {{
    background: linear-gradient(135deg, rgba(0,255,136,0.15) 0%, rgba(17,24,39,0.9) 100%);
    border: 2px solid var(--accent-green); border-radius: 12px; padding: 20px;
    margin-bottom: 24px; box-shadow: 0 0 25px rgba(0,255,136,0.25);
  }}
  .flag-banner h2 {{ color: var(--accent-green); font-size: 18px; margin-bottom: 12px; display: flex; align-items: center; gap: 8px; }}
  .flag-list {{ display: flex; flex-direction: column; gap: 10px; }}
  .flag-card {{
    display: flex; justify-content: space-between; align-items: center;
    background: #06090f; border: 1px solid rgba(0,255,136,0.4); border-radius: 8px;
    padding: 12px 18px; font-family: monospace; font-size: 16px; color: #fff; font-weight: 600;
  }}
  .btn-copy {{
    background: var(--accent-green); color: #000; border: none; padding: 6px 14px;
    border-radius: 6px; font-weight: 700; cursor: pointer; transition: 0.2s; font-size: 13px;
  }}
  .btn-copy:hover {{ background: #33ff9f; transform: scale(1.04); }}

  /* Intel Banner */
  .intel-banner {{
    background: linear-gradient(135deg, rgba(56,189,248,0.15) 0%, rgba(17,24,39,0.95) 100%);
    border: 2px solid var(--accent-cyan); border-radius: 12px; padding: 20px;
    margin-bottom: 24px; box-shadow: 0 0 25px rgba(56,189,248,0.25);
  }}
  .intel-banner h2 {{ color: var(--accent-cyan); font-size: 18px; margin-bottom: 12px; display: flex; align-items: center; gap: 8px; }}
  .intel-list {{ display: flex; flex-direction: column; gap: 10px; }}
  .intel-card {{
    display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 12px;
    background: #06090f; border: 1px solid rgba(56,189,248,0.4); border-radius: 8px;
    padding: 12px 18px; font-family: monospace; font-size: 14px; color: #fff;
  }}
  .intel-content {{ flex: 1; min-width: 250px; }}
  .intel-actions {{ display: flex; gap: 8px; align-items: center; flex-wrap: wrap; }}
  .btn-open {{
    background: var(--accent-cyan); color: #000; border: none; padding: 6px 14px;
    border-radius: 6px; font-weight: 700; cursor: pointer; transition: 0.2s; font-size: 13px; text-decoration: none;
    display: inline-flex; align-items: center; gap: 4px;
  }}
  .btn-open:hover {{ background: #7dd3fc; transform: scale(1.04); }}
  .btn-copy-sm {{
    background: var(--card-border); color: #fff; border: none; padding: 4px 10px;
    border-radius: 4px; font-weight: 600; cursor: pointer; transition: 0.2s; font-size: 11px;
  }}
  .btn-copy-sm:hover {{ background: var(--accent-cyan); color: #000; }}
  .payload-card {{
    background: #06090f; border: 1px solid var(--card-border); border-radius: 8px; padding: 14px 16px; margin-bottom: 14px;
  }}

  /* Sekmeler */
  .tabs {{ display: flex; gap: 8px; border-bottom: 1px solid var(--card-border); margin-bottom: 20px; flex-wrap: wrap; }}
  .tab-btn {{
    background: transparent; color: var(--text-muted); border: none; padding: 12px 20px;
    font-size: 14px; font-weight: 600; cursor: pointer; border-radius: 8px 8px 0 0; transition: 0.2s;
  }}
  .tab-btn:hover {{ color: var(--text-main); background: rgba(255,255,255,0.03); }}
  .tab-btn.active {{ color: var(--accent-cyan); border-bottom: 2px solid var(--accent-cyan); background: rgba(56,189,248,0.08); }}
  .tab-content {{ display: none; }}
  .tab-content.active {{ display: block; animation: fadeIn 0.25s ease; }}

  /* Kartlar & Pre */
  .card {{ background: var(--card-bg); border: 1px solid var(--card-border); border-radius: 10px; padding: 20px; margin-bottom: 20px; }}
  .card h3 {{ font-size: 16px; margin-bottom: 14px; color: var(--accent-cyan); display: flex; align-items: center; gap: 8px; }}
  pre {{
    background: #06090f; color: #a5f3fc; padding: 16px; border-radius: 8px;
    font-size: 12px; font-family: monospace; max-height: 480px; overflow-y: auto; border: 1px solid #1e293b;
    white-space: pre-wrap; word-break: break-all;
  }}

  /* Galeri */
  .grid-container {{ text-align: center; margin-bottom: 24px; }}
  .grid-container img {{ max-width: 100%; border-radius: 8px; border: 1px solid var(--card-border); }}
  .gallery-grid {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(200px, 1fr)); gap: 14px; }}
  .gallery-item {{
    background: #06090f; border: 1px solid var(--card-border); border-radius: 8px;
    overflow: hidden; cursor: pointer; transition: 0.2s; text-align: center;
  }}
  .gallery-item:hover {{ transform: translateY(-3px); border-color: var(--accent-cyan); }}
  .gallery-item img {{ width: 100%; height: 160px; object-fit: contain; background: #000; }}
  .gallery-item .label {{ padding: 8px; font-size: 12px; color: #e2e8f0; font-family: monospace; }}

  /* Full-Screen Stego Viewer Modal (Zoom & Klavye Gezgini) */
  .modal {{
    display: none; position: fixed; top: 0; left: 0; width: 100vw; height: 100vh;
    background: rgba(5, 8, 15, 0.96); backdrop-filter: blur(10px);
    z-index: 9999; flex-direction: column; justify-content: space-between; align-items: center;
    user-select: none;
  }}
  .modal-header {{
    width: 100%; display: flex; justify-content: space-between; align-items: center;
    padding: 12px 24px; background: rgba(17, 24, 39, 0.9); border-bottom: 1px solid var(--card-border);
    z-index: 10;
  }}
  .modal-title-box {{ display: flex; align-items: center; gap: 12px; }}
  .modal-title {{ font-size: 16px; font-weight: 700; color: #fff; font-family: monospace; }}
  .modal-controls {{ display: flex; align-items: center; gap: 8px; }}
  .modal-btn {{
    background: #1f2937; color: #fff; border: 1px solid #374151; padding: 6px 12px;
    border-radius: 6px; font-size: 13px; font-weight: 600; cursor: pointer; transition: 0.2s;
    display: inline-flex; align-items: center; gap: 4px;
  }}
  .modal-btn:hover {{ background: var(--accent-cyan); color: #000; border-color: var(--accent-cyan); }}
  .modal-btn.active {{ background: var(--accent-green); color: #000; border-color: var(--accent-green); }}
  .modal-close-btn {{
    background: #dc2626; color: #fff; border: none; padding: 6px 14px;
    border-radius: 6px; font-weight: bold; cursor: pointer; transition: 0.2s; font-size: 14px;
  }}
  .modal-close-btn:hover {{ background: #ef4444; transform: scale(1.05); }}

  .modal-body {{
    flex: 1; width: 100%; display: flex; justify-content: space-between; align-items: center;
    position: relative; overflow: hidden;
  }}
  .modal-viewport {{
    flex: 1; height: 100%; display: flex; justify-content: center; align-items: center;
    overflow: hidden; position: relative; cursor: grab;
  }}
  .modal-viewport:active {{ cursor: grabbing; }}
  .modal-viewport img {{
    max-width: 90%; max-height: 85%; object-fit: contain;
    transition: transform 0.05s ease-out; transform-origin: center center;
    image-rendering: pixelated;
  }}
  .modal-viewport img.smooth-mode {{
    image-rendering: auto;
  }}

  /* Nav Arrows */
  .modal-nav-btn {{
    position: absolute; top: 50%; transform: translateY(-50%);
    width: 52px; height: 52px; border-radius: 50%;
    background: rgba(17, 24, 39, 0.85); border: 1px solid var(--accent-cyan);
    color: var(--accent-cyan); font-size: 26px; font-weight: bold;
    display: flex; justify-content: center; align-items: center;
    cursor: pointer; transition: 0.2s; z-index: 10;
  }}
  .modal-nav-btn:hover {{
    background: var(--accent-cyan); color: #000; transform: translateY(-50%) scale(1.1);
    box-shadow: 0 0 20px rgba(56,189,248,0.5);
  }}
  .modal-nav-btn.prev-btn {{ left: 24px; }}
  .modal-nav-btn.next-btn {{ right: 24px; }}

  .modal-footer {{
    width: 100%; padding: 10px 24px; background: rgba(17, 24, 39, 0.9);
    border-top: 1px solid var(--card-border); font-size: 12px; color: var(--text-muted);
    display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 8px;
    z-index: 10;
  }}
  .kbd-shortcut {{
    background: #1f2937; color: var(--accent-cyan); padding: 2px 6px;
    border-radius: 4px; border: 1px solid #374151; font-family: monospace; font-size: 11px;
  }}

  /* Tablolar */
  table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
  th, td {{ padding: 10px 14px; text-align: left; border-bottom: 1px solid var(--card-border); }}
  th {{ color: var(--accent-cyan); background: rgba(255,255,255,0.02); }}
  tr:hover {{ background: rgba(255,255,255,0.02); }}
  a {{ color: var(--accent-cyan); text-decoration: none; }}
  a:hover {{ text-decoration: underline; }}

  @keyframes fadeIn {{ from {{ opacity: 0; transform: translateY(4px); }} to {{ opacity: 1; transform: translateY(0); }} }}
</style>
</head>
<body>
<div class="container">

  <header>
    <div class="header-top">
      <div class="header-title">
        <h1>🕵️ Stegsolve CTF Raporu: {html.escape(file_name)}</h1>
      </div>
      <div class="badge">Siber İstihbarat & Steganografi</div>
    </div>
    <div class="meta-grid">
      <div class="meta-item"><strong>Dosya:</strong> {html.escape(file_name)}</div>
      <div class="meta-item"><strong>Boyut:</strong> {size_fmt}</div>
      <div class="meta-item"><strong>Format:</strong> {self.file_type.upper()} ({os.path.splitext(self.file_path)[1].lower()})</div>
      <div class="meta-item"><strong>Tarih:</strong> {datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</div>
      <div class="meta-item" style="grid-column: 1 / -1;"><strong>SHA256:</strong> <span style="font-family: monospace;">{self.file_hash}</span></div>
    </div>
  </header>
"""

        # Bayrak Bildirimi (Bulunduysa)
        if flags:
            html_content += f"""
  <div class="flag-banner">
    <h2>🚩 MUHTEMEL BAYRAKLAR TESPİT EDİLDİ! ({len(flags)} adet)</h2>
    <div class="flag-list">
"""
            for fl in flags:
                html_content += f"""
      <div class="flag-card">
        <span>{html.escape(fl)}</span>
        <button class="btn-copy" onclick="copyText('{html.escape(fl)}')">📋 Kopyala</button>
      </div>
"""
            html_content += """
    </div>
  </div>
"""

        # Çözümlenen Gizli Veriler & İstihbarat Bildirimi (CyberChef)
        if self.decoded_findings:
            html_content += f"""
  <div class="intel-banner">
    <h2>💡 ÇÖZÜMLENEN GİZLİ VERİLER & İSTİHBARAT (CyberChef - {len(self.decoded_findings)} adet)</h2>
    <div class="intel-list">
"""
            for df in self.decoded_findings:
                m = df['method']
                src = df['source']
                orig = df['original']
                dec = df['decoded']
                ftype = df['finding_type']
                urls = df.get('urls', [])
                
                open_link_btn = ""
                if urls:
                    open_link_btn = f'<a href="{html.escape(urls[0])}" target="_blank" class="btn-open">🔗 Bağlantıyı Aç</a>'

                html_content += f"""
      <div class="intel-card">
        <div class="intel-content">
          <div style="display: flex; gap: 8px; align-items: center; margin-bottom: 6px; flex-wrap: wrap;">
            <span class="badge" style="border: none; background: rgba(56,189,248,0.2); color: var(--accent-cyan);">{html.escape(src)}</span>
            <span class="badge" style="border: none; background: rgba(245,158,11,0.2); color: var(--accent-amber);">{html.escape(m)}</span>
            <span class="badge" style="border: none; background: rgba(0,255,136,0.2); color: var(--accent-green);">{html.escape(ftype)}</span>
          </div>
          <div style="font-size: 11px; color: var(--text-muted); margin-bottom: 4px;">Orijinal: <code style="color: #94a3b8;">{html.escape(orig[:120])}</code></div>
          <div style="font-size: 15px; font-weight: bold; color: var(--accent-green); word-break: break-all;">
            Çözümlenen: {html.escape(dec)}
          </div>
        </div>
        <div class="intel-actions">
          <button class="btn-copy" onclick="copyText('{html.escape(dec)}')">📋 Kopyala</button>
          {open_link_btn}
        </div>
      </div>
"""
            html_content += """
    </div>
  </div>
"""

        # Sekme Butonları
        html_content += """
  <div class="tabs">
    <button class="tab-btn active" onclick="openTab('tab-summary')">🚩 Özet & Bulgular</button>
    <button class="tab-btn" onclick="openTab('tab-bitplanes')">🖼️ Bit Düzlemleri</button>
"""
        if spec_img:
            html_content += """    <button class="tab-btn" onclick="openTab('tab-audio')">🎵 Ses & Spektrogram</button>\n"""

        html_content += """    <button class="tab-btn" onclick="openTab('tab-reports')">🛠️ Araç Raporları</button>
    <button class="tab-btn" onclick="openTab('tab-files')">📁 Çıkarılan Dosyalar</button>
  </div>
"""

        # 1. SEKME: ÖZET & BULGULAR
        html_content += f"""
  <div id="tab-summary" class="tab-content active">
    <div class="card">
      <h3>📋 FOUND_FLAGS.txt Özeti</h3>
      <pre>{html.escape(raw_flags_text) if raw_flags_text else "Herhangi bir kritik bayrak eşleşmesi bulunamadı."}</pre>
    </div>
"""
        # Çıkarılan Dosyalar & İçerikleri (Varsa)
        if self.extracted_files_meta:
            html_content += """
    <div class="card">
      <h3>🔓 Çıkarılan Dosyalar & İçerik Önizlemeleri</h3>
"""
            for meta in self.extracted_files_meta:
                fname = meta['filename']
                src = meta['source']
                fsize = meta['size']
                rel_path = meta['relpath']
                sz_str = f"{fsize / 1024:.2f} KB" if fsize > 1024 else f"{fsize} B"
                
                content_html = ""
                if meta.get('content'):
                    escaped_cnt = html.escape(meta['content'])
                    clean_for_js = meta['content'].replace('\n', ' ').replace('\r', '').replace("'", "\\'")
                    content_html = f"""
      <div style="margin-top: 8px;">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 4px;">
          <span style="font-size: 11px; color: var(--accent-cyan); font-weight: 600;">Dosya İçeriği:</span>
          <button class="btn-copy-sm" onclick="copyText('{clean_for_js}')">📋 Kopyala</button>
        </div>
        <pre style="margin: 0; padding: 10px 14px; font-size: 12px; max-height: 180px;">{escaped_cnt}</pre>
      </div>
"""
                decoded_html = ""
                if meta.get('decoded_info'):
                    clean_dec_js = meta['decoded_info'].replace("'", "\\'")
                    decoded_html = f"""
      <div style="background: rgba(0,255,136,0.08); border: 1px solid rgba(0,255,136,0.3); border-radius: 6px; padding: 10px 14px; margin-top: 8px; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 8px;">
        <div>
          <span style="font-size: 11px; color: var(--accent-green); font-weight: bold;">🧠 CyberChef Otomatik Çözüm:</span>
          <div style="font-family: monospace; font-size: 14px; color: #fff; font-weight: 600; word-break: break-all; margin-top: 2px;">{html.escape(meta['decoded_info'])}</div>
        </div>
        <button class="btn-copy" style="padding: 4px 10px; font-size: 11px;" onclick="copyText('{clean_dec_js}')">📋 Kopyala</button>
      </div>
"""
                html_content += f"""
      <div class="payload-card">
        <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 8px;">
          <div>
            <strong style="color: #fff; font-size: 14px;">📄 {html.escape(fname)}</strong>
            <span class="badge" style="border: none; background: rgba(56,189,248,0.15); color: var(--accent-cyan); margin-left: 8px;">{html.escape(src)}</span>
            <span style="font-size: 12px; color: var(--text-muted); margin-left: 6px;">({sz_str})</span>
          </div>
          <a href="{html.escape(rel_path)}" target="_blank" download class="btn-open" style="padding: 4px 10px; font-size: 11px;">💾 Dosyayı İndir</a>
        </div>
        {content_html}
        {decoded_html}
      </div>
"""
            html_content += """
    </div>
"""

        if fixed_img:
            html_content += f"""
    <div class="card" style="border: 2px solid var(--accent-green); background: rgba(0, 255, 136, 0.03);">
      <h3 style="color: var(--accent-green);">🔧 Düzeltilmiş Görsel ({fixed_img[1]})</h3>
      <p style="margin-bottom: 12px; color: var(--text-muted);">Başlık (Header/SOF/IHDR) manipülasyonu tespit edildi ve gizlenen pikseller başarıyla kurtarıldı:</p>
      <div style="text-align: center;">
        <img src="{fixed_img[0]}" onclick="openModal('{fixed_img[0]}')" style="max-width: 100%; max-height: 480px; border-radius: 8px; border: 1px solid var(--accent-green); cursor: zoom-in;" />
      </div>
      <p style="font-size: 13px; color: var(--accent-green); margin-top: 10px; font-weight: 500;">
        💡 İpucu: Görselin kurtarılan yeni piksellerinde gizlenmiş bayrak metinlerini veya mesajları inceleyebilirsiniz.
      </p>
    </div>
"""
        html_content += """  </div>\n"""

        # 2. SEKME: BİT DÜZLEMLERİ
        html_content += """
  <div id="tab-bitplanes" class="tab-content">
"""
        if grid_img:
            html_content += f"""
    <div class="card grid-container">
      <h3>📊 Bit Düzlemleri Izgarası (Grid Görünümü)</h3>
      <img src="{grid_img}" alt="Bit Planes Grid" onclick="openModal('{grid_img}')" style="cursor: zoom-in;" />
      <p style="font-size: 12px; color: var(--text-muted); margin-top: 8px;">(Büyütmek için görsele tıklayın)</p>
    </div>
"""
        if bit_plane_files:
            html_content += """
    <div class="card">
      <h3>🔍 Ayrı Kanal ve Bit Görselleri (Tıkla-Büyüt)</h3>
      <div class="gallery-grid">
"""
            for label, rel_p in bit_plane_files:
                html_content += f"""
        <div class="gallery-item" onclick="openModal('{rel_p}')">
          <img src="{rel_p}" loading="lazy" />
          <div class="label">{html.escape(label)}</div>
        </div>
"""
            html_content += """
      </div>
    </div>
"""
        html_content += """  </div>\n"""

        # 3. SEKME: SES & SPEKTROGRAM (Varsa)
        if spec_img:
            html_content += f"""
  <div id="tab-audio" class="tab-content">
    <div class="card">
      <h3>🎵 Frekans Spektrogramı (Spectrogram)</h3>
      <p style="color: var(--text-muted); margin-bottom: 14px;">Ses frekansları görselleştirildi. Görsel içine çizilmiş gizli bayrakları aşağıdan inceleyebilirsiniz:</p>
      <div style="text-align: center;">
        <img src="{spec_img}" onclick="openModal('{spec_img}')" style="max-width: 100%; border-radius: 8px; cursor: zoom-in; border: 1px solid var(--card-border);" />
      </div>
    </div>
  </div>
"""

        # 4. SEKME: ARAÇ RAPORLARI
        html_content += """
  <div id="tab-reports" class="tab-content">
"""
        for rf, title, content in reports_data:
            html_content += f"""
    <div class="card">
      <h3>{title} ({rf})</h3>
      <pre>{content}</pre>
    </div>
"""
        html_content += """  </div>\n"""

        # 5. SEKME: ÇIKARILAN DOSYALAR
        html_content += """
  <div id="tab-files" class="tab-content">
    <div class="card">
      <h3>📁 Otomatik Çıkartılan Dosyalar & Payload'lar</h3>
"""
        if extracted_files:
            html_content += """
      <table>
        <thead>
          <tr>
            <th>Dosya Adı</th>
            <th>Kategori</th>
            <th>Boyut</th>
            <th>İndir / İncele</th>
          </tr>
        </thead>
        <tbody>
"""
            for fname, rel_path, fsize, cat in extracted_files:
                sz_str = f"{fsize / 1024:.2f} KB" if fsize > 1024 else f"{fsize} B"
                matched_meta = next((m for m in self.extracted_files_meta if m['filename'] == fname), None)
                
                preview_subrow = ""
                if matched_meta and matched_meta.get('content'):
                    clean_sub_js = matched_meta['content'].replace('\n', ' ').replace('\r', '').replace("'", "\\'")
                    decoded_note = ""
                    if matched_meta.get('decoded_info'):
                        decoded_note = f"""
                    <div style="margin-top: 8px; font-size: 13px; color: var(--accent-green); background: rgba(0,255,136,0.06); padding: 6px 10px; border-radius: 6px; border: 1px solid rgba(0,255,136,0.2);">
                      🧠 <strong>CyberChef Otomatik Çözümü:</strong> {html.escape(matched_meta['decoded_info'])}
                    </div>
"""
                    preview_subrow = f"""
          <tr>
            <td colspan="4" style="background: rgba(0,0,0,0.3); padding: 8px 14px 12px 14px; border-bottom: 1px solid var(--card-border);">
              <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 4px;">
                <span style="font-size: 11px; color: var(--accent-cyan); font-weight: 600;">Dosya İçeriği:</span>
                <button class="btn-copy-sm" onclick="copyText('{clean_sub_js}')">📋 Kopyala</button>
              </div>
              <pre style="margin: 0; padding: 6px 10px; font-size: 12px; max-height: 120px;">{html.escape(matched_meta['content'])}</pre>
              {decoded_note}
            </td>
          </tr>
"""
                html_content += f"""
          <tr>
            <td><strong>{html.escape(fname)}</strong></td>
            <td><span class="badge" style="border: none; background: rgba(56,189,248,0.15); color: var(--accent-cyan);">{cat}</span></td>
            <td>{sz_str}</td>
            <td><a href="{rel_path}" target="_blank" download>💾 İndir</a></td>
          </tr>
{preview_subrow}
"""
            html_content += """
        </tbody>
      </table>
"""
        else:
            html_content += """<p style="color: var(--text-muted);">Bu analizde gömülü bir dosya çıkartılmadı.</p>"""

        html_content += f"""
    </div>
  </div>

</div>

<!-- Full-Screen Stego Viewer Modal (Zoom & Klavye Gezgini) -->
<div id="imageModal" class="modal">
  <div class="modal-header">
    <div class="modal-title-box">
      <span id="modalTitle" class="modal-title">Görsel</span>
      <span id="modalCounter" class="badge">1 / 1</span>
    </div>
    <div class="modal-controls">
      <button class="modal-btn" onclick="zoomStep(-0.25)" title="Uzaklaş (Tuş: - veya Aşağı Ok)">🔍 -</button>
      <span id="zoomLevel" style="font-family: monospace; font-size: 12px; min-width: 45px; text-align: center; color: var(--accent-cyan);">100%</span>
      <button class="modal-btn" onclick="zoomStep(+0.25)" title="Yakınlaş (Tuş: + veya Yukarı Ok)">🔍 +</button>
      <button class="modal-btn" onclick="resetZoom()" title="Yakınlaştırmayı Sıfırla (Tuş: R veya 0)">🎯 1:1</button>
      <button id="btnPixelated" class="modal-btn active" onclick="togglePixelated()" title="Piksel Keskinliği / Yumuşatma (Tuş: P)">👾 Piksel Modu</button>
      <button class="modal-close-btn" onclick="closeModal()" title="Kapat (Tuş: ESC)">✕</button>
    </div>
  </div>

  <div class="modal-body">
    <button class="modal-nav-btn prev-btn" onclick="prevImage(event)" title="Önceki Görsel (Tuş: Sol Ok / A)">❮</button>
    <div id="modalViewport" class="modal-viewport">
      <img id="modalImg" src="" draggable="false" />
    </div>
    <button class="modal-nav-btn next-btn" onclick="nextImage(event)" title="Sonraki Görsel (Tuş: Sağ Ok / D)">❯</button>
  </div>

  <div class="modal-footer">
    <div>
      <span>⌨️ <strong>Klavye Kısayolları:</strong> </span>
      <span class="kbd-shortcut">◀ Sol Ok / A</span> Önceki &nbsp;|&nbsp;
      <span class="kbd-shortcut">▶ Sağ Ok / D</span> Sonraki &nbsp;|&nbsp;
      <span class="kbd-shortcut">▲ / ▼ / Tekerlek</span> Zoom &nbsp;|&nbsp;
      <span class="kbd-shortcut">Çift Tık</span> 3x Yakınlaş &nbsp;|&nbsp;
      <span class="kbd-shortcut">Sürükle</span> Kaydır &nbsp;|&nbsp;
      <span class="kbd-shortcut">P</span> Piksel Modu &nbsp;|&nbsp;
      <span class="kbd-shortcut">R</span> Sıfırla &nbsp;|&nbsp;
      <span class="kbd-shortcut">ESC</span> Kapat
    </div>
    <div style="color: var(--accent-green); font-size: 11px;">
      ⚡ Stegsolve Canlı Bit Düzlemi Gezgini
    </div>
  </div>
</div>

<script>
const galleryImages = {gallery_json};
let currentIndex = 0;
let currentScale = 1.0;
let currentTranslateX = 0;
let currentTranslateY = 0;
let isDragging = false;
let startX = 0;
let startY = 0;
let isPixelated = true;

const modal = document.getElementById('imageModal');
const viewport = document.getElementById('modalViewport');
const modalImg = document.getElementById('modalImg');
const zoomLevelEl = document.getElementById('zoomLevel');
const modalTitleEl = document.getElementById('modalTitle');
const modalCounterEl = document.getElementById('modalCounter');
const btnPixelated = document.getElementById('btnPixelated');

function updateTransform() {{
  modalImg.style.transform = 'translate(' + currentTranslateX + 'px, ' + currentTranslateY + 'px) scale(' + currentScale + ')';
  zoomLevelEl.innerText = Math.round(currentScale * 100) + '%';
  viewport.style.cursor = currentScale > 1.05 ? (isDragging ? 'grabbing' : 'grab') : 'default';
}}

function resetZoom() {{
  currentScale = 1.0;
  currentTranslateX = 0;
  currentTranslateY = 0;
  updateTransform();
}}

function zoomStep(delta, mouseX, mouseY) {{
  const newScale = Math.min(Math.max(currentScale + delta, 0.25), 15.0);
  if (mouseX !== undefined && mouseY !== undefined) {{
    const rect = viewport.getBoundingClientRect();
    const offsetX = mouseX - rect.left - rect.width / 2;
    const offsetY = mouseY - rect.top - rect.height / 2;
    const ratio = newScale / currentScale;
    currentTranslateX = offsetX - (offsetX - currentTranslateX) * ratio;
    currentTranslateY = offsetY - (offsetY - currentTranslateY) * ratio;
  }}
  currentScale = newScale;
  updateTransform();
}}

function togglePixelated() {{
  isPixelated = !isPixelated;
  if (isPixelated) {{
    modalImg.classList.remove('smooth-mode');
    btnPixelated.classList.add('active');
  }} else {{
    modalImg.classList.add('smooth-mode');
    btnPixelated.classList.remove('active');
  }}
}}

function showImage(idx) {{
  if (!galleryImages || galleryImages.length === 0) return;
  if (idx < 0) idx = galleryImages.length - 1;
  if (idx >= galleryImages.length) idx = 0;
  currentIndex = idx;
  const item = galleryImages[currentIndex];
  modalImg.src = item.src;
  modalTitleEl.innerText = item.title;
  modalCounterEl.innerText = (currentIndex + 1) + ' / ' + galleryImages.length;
  // Resim değiştiğinde mevcut zoom ve pan pozisyonunu koru
  updateTransform();
}}

function nextImage(e) {{
  if (e) e.stopPropagation();
  showImage(currentIndex + 1);
}}

function prevImage(e) {{
  if (e) e.stopPropagation();
  showImage(currentIndex - 1);
}}

function openModal(src) {{
  if (!galleryImages || galleryImages.length === 0) return;
  let foundIdx = galleryImages.findIndex(img => img.src === src || src.endsWith(img.src) || img.src.endsWith(src));
  if (foundIdx === -1) {{
    foundIdx = 0;
  }}
  // Sayfadan yeni bir resim tıklandığında zoom'u 1:1 başlat
  resetZoom();
  showImage(foundIdx);
  modal.style.display = 'flex';
  document.body.style.overflow = 'hidden';
}}

function closeModal() {{
  modal.style.display = 'none';
  document.body.style.overflow = 'auto';
  resetZoom();
}}

// Fare Tekerleği ile Zoom (Cursor Odaklı)
viewport.addEventListener('wheel', (e) => {{
  e.preventDefault();
  const delta = e.deltaY < 0 ? 0.25 : -0.25;
  zoomStep(delta, e.clientX, e.clientY);
}}, {{ passive: false }});

// Sürükle & Bırak (Pan)
viewport.addEventListener('mousedown', (e) => {{
  if (e.button !== 0) return;
  isDragging = true;
  startX = e.clientX - currentTranslateX;
  startY = e.clientY - currentTranslateY;
  viewport.style.cursor = 'grabbing';
}});

window.addEventListener('mousemove', (e) => {{
  if (!isDragging) return;
  currentTranslateX = e.clientX - startX;
  currentTranslateY = e.clientY - startY;
  updateTransform();
}});

window.addEventListener('mouseup', () => {{
  if (isDragging) {{
    isDragging = false;
    viewport.style.cursor = currentScale > 1.05 ? 'grab' : 'default';
  }}
}});

// Çift Tık ile Hızlı Zoom (1x <-> 3x)
viewport.addEventListener('dblclick', (e) => {{
  if (currentScale > 1.2) {{
    resetZoom();
  }} else {{
    zoomStep(2.0, e.clientX, e.clientY);
  }}
}});

// Klavye Dinleyicileri (Ok Tuşları, Harfler, ESC)
window.addEventListener('keydown', (e) => {{
  if (modal.style.display !== 'flex') return;

  if (e.key === 'ArrowRight' || e.key === 'd' || e.key === 'D') {{
    nextImage();
  }} else if (e.key === 'ArrowLeft' || e.key === 'a' || e.key === 'A') {{
    prevImage();
  }} else if (e.key === 'ArrowUp' || e.key === '+' || e.key === '=') {{
    e.preventDefault();
    zoomStep(0.25);
  }} else if (e.key === 'ArrowDown' || e.key === '-') {{
    e.preventDefault();
    zoomStep(-0.25);
  }} else if (e.key === '0' || e.key === 'r' || e.key === 'R') {{
    resetZoom();
  }} else if (e.key === 'p' || e.key === 'P') {{
    togglePixelated();
  }} else if (e.key === 'Escape') {{
    closeModal();
  }}
}});

function openTab(tabId) {{
  document.querySelectorAll('.tab-content').forEach(el => el.classList.remove('active'));
  document.querySelectorAll('.tab-btn').forEach(el => el.classList.remove('active'));
  document.getElementById(tabId).classList.add('active');
  event.currentTarget.classList.add('active');
}}

function copyText(txt) {{
  navigator.clipboard.writeText(txt).then(() => {{
    alert("Kopyalandı: " + txt);
  }}).catch(() => {{
    prompt("Kopyalamak için Ctrl+C tuşlayın:", txt);
  }});
}}
</script>
</body>
</html>
"""
        # Kaydet
        html_report_path = os.path.join(self.output_dir, "index.html")
        with open(html_report_path, "w", encoding="utf-8") as hf:
            hf.write(html_content.replace('\x00', ''))
        print(f"[+] 🌐 İnteraktif HTML Raporu hazır: {html_report_path}")

    def start_analysis(self) -> None:
        print(f"=== SİBER İSTİHBARAT STEGANOGRAFİ ARACI ===")
        print(f"Hedef Dosya: {self.file_path}\n")
        
        # 1. Aşama: PNG Bütünlük ve IHDR CRC / JPEG Anomali Taraması
        ext = os.path.splitext(self.file_path)[1].lower()
        if ext == '.png':
            self.check_and_fix_png_ihdr()
        elif ext in ['.jpg', '.jpeg']:
            self.check_and_fix_jpeg_dimensions()
            self.check_and_carve_jpeg_anomalies()

        # 2. Aşama: Her dosya için geçerli temel analizler
        self.run_exiftool()
        # ExifTool çalıştıktan sonra Exif boyut bilgisi ile tekrar kontrol et (ilk adımda yakalanamadıysa)
        if ext in ['.jpg', '.jpeg'] and not os.path.exists(os.path.join(self.output_dir, "fixed_dimensions.jpg")):
            self.check_and_fix_jpeg_dimensions()

        self.run_strings()
        self.run_binwalk()

        # 3. Aşama: Özel Steganografi Araçları (zsteg & steghide)
        if ext in ['.png', '.bmp']:
            self.run_zsteg()

        if ext in ['.jpg', '.jpeg', '.bmp', '.wav', '.au']:
            self.run_steghide()
            if ext in ['.jpg', '.jpeg']:
                # Steghide uyarısı verdiyse bozuk/ekstra baytları tekrar kontrol edip çıkart ve boyutu dene
                if not os.path.exists(os.path.join(self.output_dir, "fixed_dimensions.jpg")):
                    self.check_and_fix_jpeg_dimensions()
                self.check_and_carve_jpeg_anomalies()
        elif ext in ['.png', '.webp', '.tiff', '.gif']:
            print(f"[*] Bilgi: steghide yalnızca JPEG, BMP ve WAV/AU formatlarını destekler ('{ext}' için zsteg/bit plane kullanıldı).")

        # 4. Aşama: Dosya tipine göre Derin Görsel veya Ses Analizi
        target_img = self.file_path
        cand_fixed_jpg = os.path.join(self.output_dir, "fixed_dimensions.jpg")
        cand_fixed_png = os.path.join(self.output_dir, "fixed_dimensions.png")
        if os.path.exists(cand_fixed_jpg):
            target_img = cand_fixed_jpg
        elif os.path.exists(cand_fixed_png):
            target_img = cand_fixed_png

        if self.file_type == "video":
            frames = self.extract_video_frames()
            print(f"[+] Toplam {len(frames)} kare üzerinde Bit Düzlemi analizi başlıyor...")
            for frame in tqdm(frames, desc="Kareler İşleniyor"):
                self.analyze_bit_planes(frame)
                
        elif self.file_type == "image":
            print("[+] Görüntü üzerinde Bit Düzlemi analizi başlıyor (Grid + 0-7 Tüm Düzlemler)...")
            self.analyze_bit_planes(target_img)
            self.run_visual_morse_analysis(target_img)

        elif self.file_type == "audio":
            self.run_audio_analysis()

        # 5. Aşama: Otomatik Decode Sihirbazı (Mini CyberChef)
        self.run_decode_wizard()

        # 6. Aşama: Sıfır Bağımlılıklı İnteraktif HTML Raporu
        self.generate_html_report()

        print(f"\n[+] Analiz Tamamlandı! Tüm raporlar '{self.output_dir}' klasöründe.")
        print(f"[+] 🌐 İnteraktif Web Raporu: {os.path.join(self.output_dir, 'index.html')}")

        # 7. Aşama: Raporu Otomatik Firefox ile Aç
        if self.open_browser:
            self.open_report_in_browser()

    def open_report_in_browser(self) -> None:
        """Oluşturulan index.html raporunu otomatik olarak Firefox (veya sistem varsayılan tarayıcısı) ile açar."""
        html_report_path = os.path.abspath(os.path.join(self.output_dir, "index.html"))
        if not os.path.exists(html_report_path):
            return

        # Headless veya DISPLAY olmayan ortam kontrolü (SSH oturumu ve DISPLAY yoksa)
        if sys.platform != 'darwin' and 'DISPLAY' not in os.environ and 'WAYLAND_DISPLAY' not in os.environ:
            print("[*] Bilgi: Grafik ekranı (DISPLAY) bulunamadığı için tarayıcı otomatik başlatılmadı.")
            return

        print("[+] Rapor Firefox tarayıcısında açılıyor...")
        firefox_bin = self._find_executable('firefox') or self._find_executable('firefox-esr')

        opened = False
        try:
            if firefox_bin:
                subprocess.Popen([firefox_bin, html_report_path],
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                 start_new_session=True)
                opened = True
            elif sys.platform == 'darwin':
                res = subprocess.run(['open', '-a', 'Firefox', html_report_path],
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                if res.returncode == 0:
                    opened = True
                else:
                    subprocess.run(['open', html_report_path],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    opened = True
            elif sys.platform.startswith('linux'):
                subprocess.Popen(['xdg-open', html_report_path],
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                 start_new_session=True)
                opened = True
        except Exception:
            opened = False

        if not opened:
            try:
                import webbrowser
                webbrowser.open(f"file://{html_report_path}")
                opened = True
            except Exception:
                pass

        if opened:
            print(f"[✓] 🌐 Rapor tarayıcıda başlatıldı: file://{html_report_path}")
        else:
            print(f"[-] Tarayıcı otomatik başlatılamadı. Raporu manuel açabilirsiniz: {html_report_path}")

# --- KULLANIM ---
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Siber İstihbarat Steganografi Aracı")
    parser.add_argument("hedef", nargs='?', help="Analiz edilecek dosyanın yolu")
    parser.add_argument("--separate", action="store_true", default=True, help="Bit düzlemlerini hem grid hem ayrı ayrı kaydet (Varsayılan: Açık)")
    parser.add_argument("--no-separate", action="store_true", help="Ayrı bit düzlemlerini kaydetme, yalnızca birleşik grid görselini kaydet")
    parser.add_argument("-p", "--passphrase", type=str, default=None, help="Steghide için parola")
    parser.add_argument("-w", "--wordlist", type=str, default=None, help="Steghide için wordlist dosyası")
    parser.add_argument("-a", "--zsteg-all", action="store_true", help="zsteg için tüm yöntemleri derinlemesine tara (-a)")
    parser.add_argument("--no-browser", action="store_true", help="Rapor oluşturulduktan sonra tarayıcıyı otomatik açma")
    args = parser.parse_args()

    hedef = args.hedef
    if not hedef:
        hedef = input("Analiz edilecek dosyanın yolunu girin (Örn: banner_video_1.mp4): ")
        
    if os.path.exists(hedef):
        analyzer = StegoAnalyzer(
            hedef,
            save_separate=not args.no_separate,
            passphrase=args.passphrase,
            wordlist=args.wordlist,
            zsteg_all=args.zsteg_all,
            open_browser=not args.no_browser
        )
        analyzer.start_analysis()
    else:
        print("[-] Dosya bulunamadı!")