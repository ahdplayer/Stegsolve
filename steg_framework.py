import cv2
import numpy as np
import os
import subprocess
import re
import sys
import datetime
from tqdm import tqdm
import shutil

class StegoAnalyzer:
    def __init__(self, file_path, output_dir=None):
        self.file_path = file_path
        
        if output_dir is None:
            base_name = os.path.splitext(os.path.basename(file_path))[0]
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            self.output_dir = f"{base_name}_{timestamp}_reports"
        else:
            self.output_dir = output_dir
            
        self.file_type = self._get_file_type()
        
        # CTF Bayrak formatlarını yakalamak için Regex (Örn: SSUC{...}, flag{...}, MİT{...})
        # İstikrarlı olması için ön ekin en az 3, iç kısmın en az 4 karakter olması şartı konuldu
        self.flag_pattern = re.compile(r'[a-zA-Z0-9_]{3,30}{[a-zA-Z0-9_!@#$%^&*()-=+\\]{4,}}')
        
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)
            
        self.bit_planes_dir = os.path.join(self.output_dir, "bit_planes")
        if not os.path.exists(self.bit_planes_dir):
            os.makedirs(self.bit_planes_dir)
            
        # Sözlük yükle (macOS/Linux - Anlamlı kelime tespiti için)
        self.dictionary = set()
        dict_path = "/usr/share/dict/words"
        if os.path.exists(dict_path):
            with open(dict_path, "r", encoding="utf-8", errors="ignore") as f:
                self.dictionary = set(word.strip().lower() for word in f if len(word.strip()) > 3)

    def _get_file_type(self):
        """Dosyanın video mu yoksa fotoğraf mı olduğunu belirler."""
        video_exts = ['.mp4', '.avi', '.mov', '.mkv']
        img_exts = ['.png', '.jpg', '.jpeg', '.bmp', '.tiff']
        ext = os.path.splitext(self.file_path)[1].lower()
        
        if ext in video_exts:
            return "video"
        elif ext in img_exts:
            return "image"
        else:
            return "unknown"

    def run_exiftool(self):
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

    def run_strings(self):
        """Dosya içindeki okunabilir gizli metinleri (Strings) çıkarır."""
        print("[+] Dosya içi gizli metin (Strings) analizi yapılıyor... (min 8 karakter)")
        try:
            # -n 8: Yalnızca ardışık 8 veya daha fazla okunabilir karakter içerenleri getir (Çöp veriyi azaltır)
            result = subprocess.run(['strings', '-n', '5', self.file_path], capture_output=True, text=True)
            report_path = os.path.join(self.output_dir, "strings_report.txt")
            with open(report_path, "w") as f:
                f.write(result.stdout)
            
            self._search_flags_in_text("Strings", result.stdout)
            
            # Gelişmiş Regex Kalıpları
            patterns = {
                'URL': re.compile(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'),
                'Email': re.compile(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+'),
                'IP': re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'),
                'Base64_String': re.compile(r'\b(?:[A-Za-z0-9+/]{4}){5,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?\b'),
            }
            
            found_items = {k: set() for k in patterns}
            found_items['Meaningful_Sentence'] = set()
            found_items['Interesting_File_Or_Word'] = set()
            
            interesting_exts = ['.zip', '.rar', '.txt', '.png', '.jpg', '.pdf', '.kdbx']
            interesting_words = ['password', 'secret', 'admin', 'login', 'flag']

            for line in result.stdout.split('\n'):
                line = line.strip()
                if not line:
                    continue
                    
                # Regex ile yapısal veri ara
                for key, pattern in patterns.items():
                    for m in pattern.findall(line):
                        if key == 'Base64_String':
                            # JPEG Huffman table vb. ardışık dizilimleri (false positive) ele
                            if 'cdefghijstuvwxyz' in m.lower():
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

            # Raporlama ve Alert
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

    def _search_flags_in_text(self, source, text):
        """Verilen metin içinde Regex ile Flag formatı arar."""
        flags = self.flag_pattern.findall(text)
        if flags:
            print(f"\n[!!!] {source} İÇİNDE MUHTEMEL BAYRAK BULUNDU: {flags}")
            with open(os.path.join(self.output_dir, "FOUND_FLAGS.txt"), "a") as f:
                f.write(f"Source: {source} -> {flags}\n")

    def extract_video_frames(self):
        """Videoyu karelere böler."""
        print("[+] Video tespit edildi. Kareler çıkartılıyor...")
        frames_dir = os.path.join(self.output_dir, "frames")
        if not os.path.exists(frames_dir):
            os.makedirs(frames_dir)
            
        cmd = ['ffmpeg', '-i', self.file_path, os.path.join(frames_dir, 'frame_%04d.png')]
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return sorted([os.path.join(frames_dir, f) for f in os.listdir(frames_dir) if f.endswith('.png')])

    def analyze_bit_planes(self, image_path):
        """Bir görselin R, G, B kanallarının LSB ve MSB bitlerini analiz edip kaydeder."""
        img = cv2.imread(image_path)
        if img is None:
            return

        b, g, r = cv2.split(img)
        channels = {'Red': r, 'Green': g, 'Blue': b}

        for color_name, channel_matrix in channels.items():
            # En çok veri saklanan kritik bitleri tarıyoruz (0 = LSB, 5,6,7 = MSB)
            for bit in [0, 5, 6, 7]:
                # Bit düzlemini ayır
                bit_plane = ((channel_matrix >> bit) & 1) * 255
                
                # Bit düzlemini dosyaya kaydet
                base_name = os.path.splitext(os.path.basename(image_path))[0]
                save_path = os.path.join(self.bit_planes_dir, f"{base_name}_{color_name}_Bit_{bit}.png")
                cv2.imwrite(save_path, bit_plane)
                
            # LSB Half (Alt 4 bit)
            lsb_half = (channel_matrix & 0x0F) * 16
            save_path = os.path.join(self.bit_planes_dir, f"{base_name}_{color_name}_LSB_Half.png")
            cv2.imwrite(save_path, lsb_half)
            
            # MSB Half (Üst 4 bit)
            msb_half = (channel_matrix & 0xF0)
            save_path = os.path.join(self.bit_planes_dir, f"{base_name}_{color_name}_MSB_Half.png")
            cv2.imwrite(save_path, msb_half)

    def run_binwalk(self):
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

    def start_analysis(self):
        print(f"=== SİBER İSTİHBARAT STEGANOGRAFİ ARACI ===")
        print(f"Hedef Dosya: {self.file_path}\n")
        
        # 1. Aşama: Her dosya için geçerli temel analizler
        self.run_exiftool()
        self.run_strings()
        self.run_binwalk()

        # 2. Aşama: Dosya tipine göre Derin Görüntü İşleme
        if self.file_type == "video":
            frames = self.extract_video_frames()
            print(f"[+] Toplam {len(frames)} kare üzerinde Bit Düzlemi analizi başlıyor...")
            for frame in tqdm(frames, desc="Kareler İşleniyor"):
                self.analyze_bit_planes(frame)
                
        elif self.file_type == "image":
            print("[+] Görüntü üzerinde Bit Düzlemi analizi başlıyor...")
            self.analyze_bit_planes(self.file_path)

        print(f"\n[+] Analiz Tamamlandı! Tüm raporlar '{self.output_dir}' klasöründe.")

# --- KULLANIM ---
if __name__ == "__main__":
    if len(sys.argv) > 1:
        hedef = sys.argv[1]
    else:
        hedef = input("Analiz edilecek dosyanın yolunu girin (Örn: banner_video_1.mp4): ")
        
    if os.path.exists(hedef):
        analyzer = StegoAnalyzer(hedef)
        analyzer.start_analysis()
    else:
        print("[-] Dosya bulunamadı!")