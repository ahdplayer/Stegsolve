# Stegsolve - Siber İstihbarat ve Steganografi Aracı

Stegsolve, siber istihbarat çalışmaları ve CTF (Capture The Flag) yarışmaları için geliştirilmiş, resim ve video dosyaları üzerinde otomatik steganografi analizi yapan kapsamlı bir Python aracıdır.

Dosyaların içerisine gizlenmiş bayrakları (flag), anlamlı metinleri, zafiyetli uzantıları, exif verilerini ve LSB/MSB bit düzlemlerine gizlenmiş verileri hızlı ve etkili bir şekilde tespit etmeyi sağlar.

## 🚀 Özellikler

- **Metadata (Exif) Analizi:** Dosyaya ait Exif verilerini çıkarır ve içerisinde bilinen CTF bayrak formatlarını arar.
- **Gelişmiş Strings Analizi:** Dosya içerisindeki okunabilir metinleri çıkartır. Gelişmiş regex filtreleri ile şunları tespit eder:
  - URLs
  - Email adresleri
  - IPv4 adresleri
  - Base64 kodlanmış metinler
  - CTF Bayrakları (Örn: `flag{...}`, `SSUC{...}`)
  - Şifre, secret, admin gibi şüpheli kelimeler ve ilginç dosya uzantıları (`.zip`, `.kdbx` vb.)
  - Sözlük bazlı anlamlı İngilizce cümleler.
- **Video ve Kare (Frame) Analizi:** Girdi dosyası bir video (`.mp4`, `.avi`, `.mov`, `.mkv`) ise, `ffmpeg` kullanarak videoyu karelerine ayırır ve her bir kare üzerinde otomatik görüntü işleme yapar.
- **Bit Düzlemi (Bit Planes) Analizi:** Görüntü dosyalarının veya videodan çıkarılan karelerin Kırmızı (R), Yeşil (G) ve Mavi (B) kanallarını ayırır. Her bir kanal için kritik LSB (En Az Anlamlı Bit) ve MSB (En Çok Anlamlı Bit) analizi gerçekleştirerek gizlenmiş verileri görünür hale getirir ve kaydeder.
- **Gömülü Dosya Tespiti (Binwalk):** Dosya içerisine gizlenmiş başka dosyalar (embedded files) varsa bunları `binwalk` yardımıyla tespit eder ve otomatik olarak dışarı çıkartır.

## 📋 Gereksinimler

Aracın sorunsuz çalışabilmesi için sisteminizde aşağıdaki Python kütüphanelerinin ve sistem araçlarının kurulu olması gerekmektedir.

> ⚠️ **Windows Kullanıcıları İçin Önemli Not:**
> Araç içerisinde kullanılan `binwalk` (dosya çıkartma) ve `strings` komutları Linux/Unix mimarisine özeldir. Windows üzerinde doğrudan çalıştırıldığında hatalar veya donmalar yaşayabilirsiniz. Aracı tam verimlilikle, en güvenli ve sorunsuz şekilde kullanmak için **WSL (Windows Subsystem for Linux)** üzerinden çalıştırmanız şiddetle tavsiye edilir.

### Sistem Araçları

- **ExifTool:** Metadata analizleri için.
  - Linux: `sudo apt install libimage-exiftool-perl`
  - macOS: `brew install exiftool`
- **Binwalk:** Gömülü dosya analizi için.
  - Linux: `sudo apt install binwalk`
  - macOS: `brew install binwalk`
- **FFmpeg:** Video dosyalarını karelere ayırmak için.
  - Linux: `sudo apt install ffmpeg`
  - macOS: `brew install ffmpeg`
- **Strings:** Okunabilir metin analizi için.
  - Linux/macOS: Genellikle sistemde yüklü gelir.

### Python Kütüphaneleri

Gerekli Python kütüphanelerini yüklemek için:

```bash
pip install opencv-python numpy tqdm
```

## 🛠️ Kullanım

Aracı terminal üzerinden argüman vererek veya doğrudan çalıştırarak kullanabilirsiniz.

**Parametre ile kullanım:**
```bash
python steg_framework.py ornek_gorsel.png
# veya
python steg_framework.py gizli_video.mp4

# Bit düzlemlerini ızgara (grid) şekline ek olarak ayrı ayrı dosyalar halinde de kaydetmek isterseniz:
python steg_framework.py ornek_gorsel.png --separate
```

**Doğrudan kullanım:**
Sadece betiği çalıştırdığınızda sizden hedef dosya yolunu girmenizi isteyecektir.
```bash
python steg_framework.py
# Analiz edilecek dosyanın yolunu girin (Örn: banner_video_1.mp4): 
```

## 📁 Çıktılar ve Raporlama

Araç çalıştırıldığında analiz sonuçlarını düzenli bir şekilde depolamak için otomatik olarak bir klasör oluşturur. Klasör adı `[dosya_adi]_[tarih_saat]_reports` formatında olur.

Oluşturulan rapor klasörünün içeriği:

- **`exif_report.txt`**: Tüm metadata çıktılarını içerir.
- **`strings_report.txt`**: Çıkarılan tüm okunabilir metinlerin (strings) listesi.
- **`binwalk_report.txt`**: Binwalk analiz sonuçları.
- **`FOUND_FLAGS.txt`**: Analizler sonucunda bulunan olası CTF bayrakları, URL'ler, Base64 metinler, Email adresleri ve şüpheli/anlamlı metinler bu dosyada özetlenir.
- **`bit_planes/`**: (Klasör) Analiz edilen resim veya video karelerinin Red, Green, Blue kanallarındaki 0, 5, 6, 7. bit düzlemleri ile LSB/MSB yarılarının görüntülerini barındırır.
- **`frames/`**: (Sadece videolarda) Videodan çıkartılan ham png kareleri.
- **`extracted/`**: Binwalk tarafından dosya içinden çıkarılan gömülü veriler/dosyalar.

---

*Bu araç siber güvenlik araştırmacıları, adli bilişim uzmanları ve CTF oyuncularının Steganografi (Veri Gizleme) analiz süreçlerini otomatize etmek amacıyla tasarlanmıştır.*