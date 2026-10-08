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
- **PNG IHDR CRC Onarımı & Overlay Tespiti:** PNG dosyalarının IHDR chunk'ındaki CRC32 sağlama toplamını doğrular. CTF'lerde bayrak gizlemek amacıyla kırpılan görsel boyutlarını brute-force ile 1 milisaniyede hesaplayıp onarılmış görseli (`fixed_dimensions.png`) otomatik üretir. Ayrıca `IEND` chunk'ı sonrasına gizlenen verileri (`png_trailing_data.bin`) otomatik ayıklar.
- **JPEG SOF Boyut Manipülasyonu & Anomali Onarımı:** JPEG dosyalarının Start of Frame (SOF0 Baseline, SOF2 Progressive vb.) marker'larındaki piksel yükseklik ve genişlik değerlerini Exif/XMP metadata etiketleriyle (`ExifImageHeight`, `PixelYDimension` vb.) ve scan anomallikleriyle (`extraneous bytes`) çapraz kontrole tabi tutar. Bayrak gizlemek amacıyla kırpılan/alçaltılan JPEG boyutlarını otomatik onarır (`fixed_dimensions.jpg`), kurtarılan pikselleri web dashboard'unda özel kartla ve galeri modalında sunar, görsel analiz adımlarını doğrudan bu onarılmış tam görsel üzerinden yürütür.
- **JPEG Marker & Extraneous Byte Anomali Carving:** JPEG dosyalarının iç yapısını (Marker segmentleri, Progressive taramaları ve EOI sonrasını) inceler. Libjpeg veya Steghide'ın bildirdiği `Corrupt JPEG data: X extraneous bytes before marker` anomalilerini doğrudan yakalar. Scan bitimindeki gizli/bozuk baytları (`jpeg_extraneous_Xb_offset_0xYY.bin`) ve sıfırlardan arındırılmış çekirdek veriyi (`core.bin`) otomatik olarak dışarı aktarır (`extracted/`).
- **Akıllı Steghide & Stegseek Parola Avcısı:** Yalnızca boş parolayı (`""`) denemekle kalmaz; dosya adından, Exif metadata etiketlerinden (`Author`, `Title`, `Comment`, `Ids`) ve popüler CTF anahtar kelimelerinden dinamik parola listesi üretip otomatik dener. Sistemde `stegseek` varsa standart `rockyou.txt` sözlüğünü otomatik tespit edip milyonlarca parolayı 1 saniyede test eder.
- **Otomatik 1D Görsel Mors Kodu Tespiti:** Görsellerin üst/alt kenarlarında veya belirli piksel satırlarında gizlenmiş tek piksellik siyah-beyaz mors kodlarını (1 birim nokta, 3 birim çizgi) otomatik olarak tarar, tespit eder ve ASCII metne dönüştürerek `FOUND_FLAGS.txt` dosyasına yazar.
- **Alpha (Şeffaflık) Kanal Desteği (RGBA):** Görselleri 4 kanal (Kırmızı, Yeşil, Mavi ve Alpha) olarak inceler. Piksellerin şeffaflık bitlerine (`Alpha Bit 0-7`) gizlenen verileri yakalar ve ayrı kanal görseli olarak kaydeder.
- **Ses Spektrogramı (WAV / MP3):** Ses dosyalarının frekans spektrumunu (`ffmpeg` ile) görselleştirerek `spectrogram.png` grafiğini otomatik üretir. Ses içine çizilen görsel CTF bayraklarını anında ortaya çıkarır.
- **Otomatik Decode Sihirbazı (Mini CyberChef):** Dosya içinden çıkarılan dizgiler üzerinde otomatik Base64, Hex, ROT13, Caesar ve ters string (`reverse`) testleri yapar. Çözülen veriler içindeki flagleri ve gömülü dosyaları (ZIP, PNG, JPG vb.) otomatik çıkartır (`decoded_files/`). Standart Adobe/W3C XML şemalarını filtreleyerek sahte pozitifleri engeller.
- **🌐 Sıfır Bağımlılıklı İnteraktif Web Raporu (`index.html`):** Rapor klasörünün içinde şık, modern ve karanlık temalı tek bir HTML kontrol paneli üretir.
  - **⚡ Orijinal Stegsolve Hissi (Klavye & Zoom Gezgini):** Bit düzlemlerinde açılan modaldan **Sol (◀) / Sağ (▶) veya A / D tuşları** ile 0'dan 7'ye tüm bitler, invert ve yarılar arasında anında geçiş yapılabilir. **Fare tekerleği ile 15x'e kadar zoom**, sürükleyip kaydırma (pan), çift tıkla 3x yakınlaşma ve `P` tuşuyla piksel keskinliği (nearest-neighbor) modu bulunur.
  - **🚩 Bayrak & İstihbarat Kartları:** Bulunan tüm bayraklar ve çözümlenen gizli URL'ler (`https://pastebin.com/...`) için **"Tıkla-Kopyala"** ve doğrudan **"Bağlantıyı Aç"** butonları içerir.
  - **📁 Çıkarılan Dosyalar & Canlı Önizleme:** Steghide, zsteg ve Binwalk ile çıkartılan dosyaların ham içerikleri ve CyberChef decode sonuçları hem özet kartında hem de dosyalar tablosunda canlı görüntülenir.
- **zsteg Entegrasyonu (PNG & BMP):** PNG ve BMP dosyalarında LSB, MSB ve tüm RGB/BGR kanal kombinasyonlarını derinlemesine tarar.
  - Olası flag ve şüpheli metinleri anında tespit eder (`FOUND_FLAGS.txt` dosyasına kaydeder).
  - Dosya veya gizli veri barındıran kanalları otomatik olarak dışarı aktarır (`zsteg_extracted/`).
- **steghide Entegrasyonu (JPEG, BMP & Ses Dosyaları - WAV/AU):** Steghide ile saklanmış gömülü verileri tespit eder ve dışarı çıkarır (`steghide_extracted/`).
- **Video ve Kare (Frame) Analizi:** Girdi dosyası bir video (`.mp4`, `.avi`, `.mov`, `.mkv`) ise, `ffmpeg` kullanarak videoyu karelerine ayırır ve her bir kare üzerinde otomatik görüntü işleme yapar.
- **0'dan 7'ye Tam Bit Düzlemi (Bit Planes) Analizi:** Klasik Stegsolve aracında olduğu gibi her bir renk kanalı (Red, Green, Blue, Alpha) için **tüm 8 biti (Bit 0, 1, 2, 3, 4, 5, 6, 7)**, ters çevrilmiş negatif düzlemi (**Invert**) ve LSB/MSB yarılarını eksiksiz üretir.
- **Gömülü Dosya Tespiti (Binwalk):** Dosya içerisine gizlenmiş başka dosyalar (embedded files) varsa bunları `binwalk` yardımıyla tespit eder ve otomatik olarak dışarı çıkartır.

## 📋 Gereksinimler

Aracın sorunsuz çalışabilmesi için sisteminizde aşağıdaki Python kütüphanelerinin ve sistem araçlarının kurulu olması gerekmektedir.

> 💡 **Kali Linux Kullanıcıları İçin:**
> Araç Kali Linux üzerinde tam uyumlu çalışır. `steghide` genellikle Kali üzerinde varsayılan olarak yüklüdür veya `apt` ile anında kurulabilir.

### Sistem Araçları

- **ExifTool:** Metadata analizleri için.
  - Linux (Kali/Debian/Ubuntu): `sudo apt install libimage-exiftool-perl`
  - macOS: `brew install exiftool`
- **Binwalk:** Gömülü dosya analizi için.
  - Linux: `sudo apt install binwalk`
  - macOS: `brew install binwalk`
- **zsteg:** PNG/BMP LSB analizi için (Ruby gem).
  - Linux / macOS: `gem install zsteg`
- **steghide:** JPG/BMP/WAV steganografi çıkartma için.
  - Linux (Kali/Debian/Ubuntu): `sudo apt install steghide`
  - macOS: `sudo port install steghide`
- **FFmpeg:** Video dosyalarını karelere ayırmak için.
  - Linux: `sudo apt install ffmpeg`
  - macOS: `brew install ffmpeg`
- **Strings:** Okunabilir metin analizi için (sistemle birlikte gelir).

### Python Kütüphaneleri

Gerekli Python kütüphanelerini yüklemek için:

```bash
pip install -r requirements.txt
# veya
pip install opencv-python numpy tqdm
```

## 🛠️ Kullanım

Aracı terminal üzerinden argüman vererek veya doğrudan çalıştırarak kullanabilirsiniz.

**Temel kullanım:**
```bash
python Stegsolve.py ornek_gorsel.png
# veya ses dosyası:
python Stegsolve.py ses_kaydi.wav
# veya video:
python Stegsolve.py gizli_video.mp4
```

**Gelişmiş Parametreler:**
```bash
# zsteg ile tüm kombinasyonları derinlemesine taramak için (-a):
python Stegsolve.py hedef.png -a

# Steghide için özel parola belirtmek:
python Stegsolve.py hedef.jpg -p "gizliparola123"

# Steghide için wordlist ile deneme yapmak:
python Stegsolve.py hedef.jpg -w /usr/share/wordlists/rockyou.txt

# Not: Bit düzlemleri (hem birleşik grid hem ayrı kanal dosyaları) varsayılan olarak otomatik birlikte kaydedilir.
# Yalnızca grid kaydedilsin, ayrı kanal dosyaları oluşturulmasın isterseniz:
python Stegsolve.py ornek_gorsel.png --no-separate

# Analiz bitince Firefox'un otomatik açılmasını istemiyorsanız:
python Stegsolve.py ornek_gorsel.png --no-browser
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

- **`index.html`**: 🌐 **İnteraktif Web Dashboard'u.** Tüm analiz sonuçlarını, bayrakları (Tıkla-Kopyala), görsel bit düzlemi galerisini, spektrogramı ve indirilebilir dosyaları modern karanlık tema ile tek ekranda sunar.
- **`FOUND_FLAGS.txt`**: Analizler sonucunda bulunan olası CTF bayrakları, URL'ler, Base64 metinler, Email adresleri, zsteg ve steghide bulguları bu dosyada özetlenir.
- **`fixed_dimensions.png`**: (PNG'de bozulma varsa) IHDR CRC brute-force ile gerçek boyutları hesaplanarak otomatik onarılan görsel.
- **`png_trailing_data.bin`**: (Varsa) PNG `IEND` chunk'ı sonrasına gizlenmiş fazladan veriler (Overlay).
- **`spectrogram.png`**: (Ses dosyalarında) Sesin frekans spektrum görseli (Görsel olarak gizlenen bayrakları içerir).
- **`cyberchef_report.txt`**: Otomatik Decode Sihirbazı tarafından Base64, Hex, ROT13 ve ters string testlerinden çıkarılan çözülmüş veriler.
- **`decoded_files/`**: (Klasör) Base64 veya Hex içinden ayıklanan gömülü dosyalar (ZIP, PNG vb.).
- **`zsteg_report.txt`**: zsteg detaylı kanal ve LSB analiz raporu.
- **`zsteg_extracted/`**: (Klasör) zsteg tarafından yakalanan şüpheli kanalların ham payload verileri.
- **`steghide_report.txt`**: Steghide gömülü veri analizi ve denenen parola raporu.
- **`steghide_extracted/`**: (Klasör) Steghide ile dosyanın içinden başarıyla çıkartılan gizli dosyalar.
- **`exif_report.txt`**: Tüm metadata çıktılarını içerir.
- **`strings_report.txt`**: Çıkarılan tüm okunabilir metinlerin (strings) listesi.
- **`binwalk_report.txt`**: Binwalk analiz sonuçları.
- **`extracted_metadata.xml`**: Strings analizi sırasında bulunan devasa XMP/XML bloklarının Regex taramasından yalıtılarak kaydedildiği ham dosya.
- **`bit_planes/`**: (Klasör) Analiz edilen resim veya video karelerinin Red, Green, Blue ve Alpha kanallarındaki 0, 5, 6, 7. bit düzlemleri ile LSB/MSB yarılarının görüntüleri ve birleşik `BitPlanes_Grid.png`.
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