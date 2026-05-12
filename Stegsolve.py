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
from typing import Optional, List, Dict, Set

class StegoAnalyzer:
    def __init__(self, file_path: str, output_dir: Optional[str] = None, save_separate: bool = False) -> None:
        self.file_path = file_path
        self.save_separate = save_separate
        
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

    def analyze_bit_planes(self, image_path: str) -> None:
        """Bir görselin R, G, B kanallarının LSB ve MSB bitlerini analiz edip tek bir grid olarak kaydeder."""
        img = cv2.imread(image_path)
        if img is None:
            return

        b, g, r = cv2.split(img)
        channels = {'Red': r, 'Green': g, 'Blue': b}
        
        grid_rows = []
        height, width = img.shape[:2]
        header_height = 40
        base_name = os.path.splitext(os.path.basename(image_path))[0]

        for color_name, channel_matrix in channels.items():
            row_images = []
            color_bgr = (0, 0, 255) if color_name == 'Red' else (0, 255, 0) if color_name == 'Green' else (255, 0, 0)
            
            variations = []
            
            # En çok veri saklanan kritik bitleri tarıyoruz (0 = LSB, 5,6,7 = MSB)
            for bit in [0, 5, 6, 7]:
                bit_plane = ((channel_matrix >> bit) & 1) * 255
                variations.append((f"{color_name} Bit {bit}", bit_plane))
                
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

    def start_analysis(self) -> None:
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
    parser = argparse.ArgumentParser(description="Siber İstihbarat Steganografi Aracı")
    parser.add_argument("hedef", nargs='?', help="Analiz edilecek dosyanın yolu")
    parser.add_argument("--separate", action="store_true", help="Bit düzlemlerini grid'e ek olarak ayrı dosyalar olarak da kaydet")
    args = parser.parse_args()

    hedef = args.hedef
    if not hedef:
        hedef = input("Analiz edilecek dosyanın yolunu girin (Örn: banner_video_1.mp4): ")
        
    if os.path.exists(hedef):
        analyzer = StegoAnalyzer(hedef, save_separate=args.separate)
        analyzer.start_analysis()
    else:
        print("[-] Dosya bulunamadı!")