# Stegsolve - Siber İstihbarat ve Steganografi Aracı

Stegsolve, siber istihbarat çalışmaları ve CTF (Capture The Flag) yarışmaları için geliştirilmiş, resim ve video dosyaları üzerinde otomatik steganografi analizi yapan kapsamlı bir Python aracıdır.

Dosyaların içerisine gizlenmiş bayrakları (flag), anlamlı metinleri, zafiyetli uzantıları, exif verilerini ve LSB/MSB bit düzlemlerine gizlenmiş verileri hızlı ve etkili bir şekilde tespit etmeyi sağlar.

## 🚀 Özellikler

- **Metadata (Exif) Analizi:** Dosyaya ait Exif verilerini çıkarır ve içerisinde bilinen CTF bayrak formatlarını arar.
- **Gelişmiş Strings ve XMP Analizi:** Dosya içerisindeki okunabilir metinleri çıkartır. Son güncellemelerle birlikte:
  - **Otomatik XML Ayıklama:** Strings içindeki devasa Adobe XMP veya XML veri bloklarını otomatik yakalar, sahte pozitifleri engellemek adına ayırır (`extracted_metadata.xml`).
  - **Sıkılaştırılmış Regex Filtreleri:** Çok daha düşük hata payı (false positive) ile şunları tespit eder:
    - URLs ve Email adresleri
    - Geçerli IPv4 adresleri (0-255 aralığı kontrolü)
    - Base64 Encoded metinler
    - CTF Bayrakları (Örn: `flag{...}`, `SiberVatan{...}`)
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
python Stegsolve.py ornek_gorsel.png
# veya
python Stegsolve.py gizli_video.mp4

# Bit düzlemlerini ızgara (grid) şekline ek olarak ayrı ayrı dosyalar halinde de kaydetmek isterseniz:
python Stegsolve.py ornek_gorsel.png --separate
```

**Doğrudan kullanım:**
Sadece betiği çalıştırdığınızda sizden hedef dosya yolunu girmenizi isteyecektir.
```bash
python Stegsolve.py
# Analiz edilecek dosyanın yolunu girin (Örn: banner_video_1.mp4): 
```

## 📁 Çıktılar ve Raporlama

Araç çalıştırıldığında analiz sonuçlarını düzenli bir şekilde depolamak için otomatik olarak bir klasör oluşturur. Klasör adı `[dosya_adi]_[tarih_saat]_reports` formatında olur.

Oluşturulan rapor klasörünün içeriği:

- **`exif_report.txt`**: Tüm metadata çıktılarını içerir.
- **`strings_report.txt`**: Çıkarılan tüm okunabilir metinlerin (strings) listesi.
- **`binwalk_report.txt`**: Binwalk analiz sonuçları.
- **`FOUND_FLAGS.txt`**: Analizler sonucunda bulunan olası CTF bayrakları, URL'ler, Base64 metinler, Email adresleri ve şüpheli/anlamlı metinler bu dosyada özetlenir.
- **`extracted_metadata.xml`**: Strings analizi sırasında bulunan devasa XMP/XML bloklarının Regex taramasından yalıtılarak kaydedildiği ham dosya (OSINT projeleri için birebir!).
- **`bit_planes/`**: (Klasör) Analiz edilen resim veya video karelerinin Red, Green, Blue kanallarındaki 0, 5, 6, 7. bit düzlemleri ile LSB/MSB yarılarının görüntülerini barındırır.
- **`frames/`**: (Sadece videolarda) Videodan çıkartılan ham png kareleri.
- **`extracted/`**: Binwalk tarafından dosya içinden çıkarılan gömülü veriler/dosyalar.

## 🖼️ Örnek Senaryo ve Çıktılar

Bir resim veya video dosyasını analiz ettiğimizde araç bize hem terminalde anlık bir rapor sunar hem de detaylı çıktıları kaydeder.

### 1. Terminal Çıktısı

```bash
$ python Stegsolve.py testimages/bul_beni_kaybolmusum.jpg

=== SİBER İSTİHBARAT STEGANOGRAFİ ARACI ===
Hedef Dosya: testimages/bul_beni_kaybolmusum.jpg

[+] Metadata (Exif) Analizi yapılıyor...
[+] Dosya içi gizli metin (Strings) analizi yapılıyor... (min 5 karakter)
[+] Binwalk ile gömülü dosya analizi yapılıyor...
[+] Binwalk: Gömülü ek veri bulunamadı (Sadece orijinal dosya imzası).
[+] Görüntü üzerinde Bit Düzlemi analizi başlıyor...

[+] Analiz Tamamlandı! Tüm raporlar 'bul_beni_kaybolmusum_20260512_191344_reports' klasöründe.
```

### 2. Metadata Analizi (`exif_report.txt`)

Aracın `ExifTool` kullanarak çıkardığı detaylı bilgilerin bir kısmı:

```text
ExifTool Version Number         : 13.55
File Name                       : bul_beni_kaybolmusum.jpg
File Size                       : 1035 kB
File Type                       : JPEG
MIME Type                       : image/jpeg
Image Size                      : 1856x2304
Megapixels                      : 4.3
```

### 3. Gömülü Dosya Analizi (`binwalk_report.txt`)

Araç otomatik olarak dosyanın içindeki yapı taşlarını inceler:

```text
DECIMAL       HEXADECIMAL     DESCRIPTION
-------------------------------------------------------------------------
0             0x0             JPEG image, total size: 1034682 bytes
```

### 4. Bit Düzlemi Görsel Analizi (Bit Planes Grid)

Araç resmin R (Red), G (Green), B (Blue) kanallarındaki çeşitli bit düzeylerini (özellikle gizli verilerin saklandığı LSB ve MSB düzlemleri) görselleştirerek analiz etmenizi sağlayan bütüncül bir harita çıkartır. Bu sayede insan gözüyle görülemeyen gizli şekiller veya metinler (LSB Steganography vb.) kolayca tespit edilebilir.

![Bit Planes Grid](bul_beni_kaybolmusum_20260512_191344_reports/bit_planes/bul_beni_kaybolmusum_BitPlanes_Grid.png)

*(Yukarıda, analizi yapılan bir görselin kanallarında gizlenmiş olası verileri ortaya çıkaran Bit Düzlemi analizinin oluşturduğu tek parça ızgara çıktısı görülmektedir.)*

> **💡 İpucu:** `FOUND_FLAGS.txt` dosyası analizin kalbidir. Herhangi bir zafiyet, şifre, CTF formatında bir bayrak, URL veya gizli bir metin tespit edilirse otomatik olarak bu dosyaya özetlenir!

---

*Bu araç siber güvenlik araştırmacıları, adli bilişim uzmanları ve CTF oyuncularının Steganografi (Veri Gizleme) analiz süreçlerini otomatize etmek amacıyla tasarlanmıştır.*