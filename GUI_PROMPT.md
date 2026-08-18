# C# WinForms Modern GUI - Detaylı Prompt

## Proje Özeti
**ilac.cc Forensic Builder** - Windows Forms uygulaması için ultra-modern, yüksek kaliteli, bol animasyonlu bir GUI tasarla.

## Teknik Gereksinimler
- **Framework**: .NET 9.0 Windows Forms (C#)
- **Dil**: C#
- **Rendering**: GDI+ (System.Drawing), DoubleBuffered = true
- **Form**: Borderless (FormBorderStyle.None), custom title bar
- **Çözünürlük**: 1280x800 minimum, responsive

---

## 🎨 RENK PALETİ

```
Ana Arkaplan:     #06040A (çok koyu mor-siyah)
Panel Arkaplan:   #0E0A14 (koyu mor)
İkincil Panel:    #181220 (biraz açık mor)
Vurgu Rengi:      #C8283C (kan kırmızısı / crimson)
İkincil Vurgu:    #E66478 (açık pembe-kırmızı)
Metin Rengi:      #E6DCEB (açık lavanta-beyaz)
Alt Metin:        #827688 (koyu gri-mor)
Hover Rengi:      #261A2E (hover için koyu mor)
Altın:            #C8A050 (altın sarısı - özel durumlar için)
```

---

## 🔷 ARKAPLAN EFEKTİ - HEX GRID + PARTICLE SİSTEMİ

### Hexagonal Grid
- Tüm ekranı kaplayan hexagon (altıgen) ızgara
- Her hexagon: 32px boyutunda, 3px boşluklu
- Hexagon'lar mouse pozisyonuna göre glow efekti yayar
- Glow yarıçapı: 200px, quadratic falloff ile azalır
- Mouse hareket ettikçe glow dalgası yayılır

### Particle Sistemi
- Ekranda 50-80 arası küçük parçacık (2-4px)
- Parçacıklar rastgele yönde yavaşça süzülür
- Parçacıklar kırmızı-pembe tonlarında, alpha 30-80 arası
- Parçacıklar ekrandan çıkınca diğer taraftan girer (loop)
- Bazı parçacıklar mouse'a çekilir (manyetik efekt)

### Pulse Efekti
- Tüm hexagon'lar sinüs dalgası ile hafifçe nefes alır
- Frekans: 0.02 rad/frame
- Alpha: 0.03 + sin(pulse) * 0.15

---

## 🌅 AÇILIŞ ANİMASYONU

1. **Fade In**: Form 0'dan 1'e opacity ile açılır (500ms)
2. **Scale In**: İçerik panelleri %95'ten %100'e scale olur
3. **Slide In**: Her bölüm değişiminde panel sağdan 40px kayarak gelir
4. **Accent Line Grow**: Bölüm başlıklarındaki altı çizgi 0'dan 640px'e büyür

---

## 📐 LAYOUT YAPISI

### Title Bar (Üst Çubuk) - 48px yükseklik
```
┌─────────────────────────────────────────────────────────┐
│ ilac.cc  Forensic Builder · Napse + Ocean + Detect AC   │  ← Gradient arka plan
│                                         [─] [✕]         │  ← Hover'da glow
└─────────────────────────────────────────────────────────┘
```
- **Gradient arka plan**: Sol → Sağ #0A0810 → #121018
- **Logo**: "ilac.cc" - kırmızı (#C8283C), bold, 14pt
- **Sürükleme**: Title bar'dan formu sürükleme
- **Butonlar**: Hover'da arka plan glow, smooth transition

### Sidebar (Sol Panel) - 240px genişlik
```
┌─────────────────────┐
│                     │
│   ilac.cc           │  ← Büyük logo, glow efekti
│   v2.1 Forensic     │  ← Alt metin
│                     │
│ ─────────────────── │  ← İnce çizgi separator
│                     │
│ ▌ Webhook          │  ← Aktif bölüm (glow border)
│   Browser          │
│   Forensic         │
│   Bypass           │
│   Advanced         │
│                     │
│ ─────────────────── │
│                     │
│  ⚒ BUILD CLIENT    │  ← Gradient buton, pulse animasyonu
│                     │
│  Forensic-grade     │
│  detection          │
└─────────────────────┘
```
- **Aktif bölüm**: Sol tarafta 3px kırmızı accent çubuk + arka plan highlight
- **Hover efekti**: Hafif arka plan aydınlanması + text glow
- **Build butonu**: Gradient (#C8283C → #E66478), hover'da genişleme + glow

### Content Area (Orta Alan)
```
┌──────────────────────────────────────────────────────────┐
│  ┌────────────────────────────────────────────────────┐  │
│  │                                                    │  │
│  │  Webhook Configuration              [grow line]    │  │  ← Glass panel
│  │  Where scan results are delivered.                 │  │
│  │  ───────────────────────────────────────────────   │  │
│  │                                                    │  │
│  │  Discord Webhook URL                               │  │
│  │  ┌──────────────────────────────────────────┐     │  │
│  │  │ https://discord.com/api/webhooks/...      │     │  │  ← Glow border input
│  │  └──────────────────────────────────────────┘     │  │
│  │                                                    │  │
│  │  [Save Webhook]  [Load Saved]  [Test Webhook]    │  │  ← Gradient butonlar
│  │                                                    │  │
│  │  Output Mode                                       │  │
│  │  ○ Discord Webhook  ○ Local JSON  ○ Both          │  │
│  │                                                    │  │
│  └────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────┘
```

### Status Bar (Alt Çubuk) - 28px
```
┌─────────────────────────────────────────────────────────┐
│ Ready                                          [====]   │  ← Progress bar
└─────────────────────────────────────────────────────────┘
```

---

## 🎭 ANİMASYON DETAYLARI

### 1. Panel Animasyonları
- **Slide-in**: Yeni panel 40px sağdan başlar, 300ms'de 0'a kayar
- **Fade-in**: Alpha 0'dan 255'e, cubic ease-out
- **Accent line**: 0'dan 640px'e 400ms'de büyür

### 2. Buton Animasyonları
- **Hover**: Arka plan rengi 200ms'de değişir
- **Click**: 100ms scale down (%95) → snap back
- **Build button**: Sürekli pulse (sinüs dalgası, 2s periyot)

### 3. Input Field Animasyonları
- **Focus**: Border glow efekti (kırmızı, 2px, blur)
- **Border alt çizgi**: Focus'ta genişler

### 4. Checkbox Animasyonları
- **Check**: Dolu kutu animasyonu (scale-in)
- **Hover**: Hafif renk değişimi

### 5. TrackBar (Slider)
- **Thumb**: Glow efekti
- **Track**: Gradient dolu

### 6. Progress Bar
- **Fill**: Smooth genişleme
- **Glow**: İlerledikçe artan glow
- **Complete**: Yeşil flash efekti

---

## 🎨 GLASSMORPHISM EFEKTİ

Tüm içerik panelleri:
```csharp
BackColor = Color.FromArgb(180, 14, 10, 20)
// Arka planda blur efekti (hex grid görünür)
// İnce kırmızı border (alpha 40)
// Hafif iç gölge
```

---

## 🔤 TYPOGRAPHY

- **Başlıklar**: Segoe UI, 16-20pt, Bold, #E6DCEB
- **Alt başlıklar**: Segoe UI, 9pt, Regular, #827688
- **Body**: Segoe UI, 9-10pt, Regular, #E6DCEB
- **Input**: Consolas, 10pt, #E6DCEB
- **Logo**: Segoe UI, 20pt, Bold, #C8283C (glow efekti ile)

---

## 📋 BÖLÜMLER (5 Adet)

### 1. Webhook
- Discord webhook URL input (geniş text box)
- Save / Load / Test butonları
- Output mode radio buttons
- Scan name input

### 2. Browser
- Enable Scan checkbox
- Include Hidden URLs checkbox
- Detect Deleted History checkbox
- Max Age trackbar (1-365 gün)
- Browser listesi (Chrome, Edge, Firefox, Opera GX, Brave, Vivaldi)

### 3. Forensic (24 scanner)
- Prefetch (.pf)
- BAM (Background Activity Moderator)
- AmCache
- ShimCache
- Loaded Modules
- Processes
- Registry
- Event Logs
- File System
- USN Journal
- Deleted Files
- Network
- Hosts File
- Drivers
- Services
- Scheduled Tasks
- Boot Config
- USB History
- Jumplists
- PcaClient
- ve diğerleri...

### 4. Bypass Detection
- Prefetch Deletion detection
- BAM Tampering detection
- Log Clearing detection
- Time Changes detection
- Test Signing Mode detection
- USN Journal Clear detection
- DMA Hardware detection
- ve diğerleri...

### 5. Advanced
- Silent Mode
- Scan All User Profiles
- Enable AI Analysis (Groq)
- Groq API Key input
- Custom Keywords input
- Output Directory + Browse butonu

---

## ⚒ BUILD FONKSİYONU

- "BUILD CLIENT" butonuna tıklandığında:
  1. Buton disabled olur, "BUILDING..." yazar
  2. Progress bar animasyonu başlar
  3. Async build işlemi yapılır
  4. Başarılı ise: Yeşil flash + mesaj kutusu
  5. Hatalı ise: Kırmızı flash + hata detay paneli
  6. Buton eski haline döner

---

## 🎯 ÖZEL EFEKTLER

### Glow Efekti (Tüm aktif elementlerde)
```csharp
// PathGradientBrush veya DrawingContext ile glow
// Renk: #C8283C (kırmızı)
// Blur radius: 8-15px
// Alpha: 40-80
```

### Ripple Efekti (Buton click)
```csharp
// Click noktasından yayılan dairesel dalga
// 300ms animasyon
// Alpha 100 → 0
```

### Tooltip'ler
- Her önemli element için hover tooltip
- Yumuşak fade-in/out
- Koyu arka plan, kırmızı border

---

## 📱 RESPONSIVE DAVRANIŞ

- Minimum 1000x650 boyut
- İçerik alanı scrollable
- Sidebar sabit genişlik
- Panel genişlikleri dinamik ayarlanır

---

## 💾 KAYIT/YÜKLEME

- Webhook URL: `%APPDATA%\ilac.cc\webhook.txt` dosyasına kaydedilir
- Uygulama açılışında otomatik yüklenir

---

## 🎪 ÖZET - NELER OLMALI

✅ Hexagonal grid arka plan (mouse interactive)
✅ Particle sistemi (süzülen parçacıklar)
✅ Smooth fade-in açılış
✅ Glassmorphism paneller
✅ Gradient butonlar
✅ Glow efektleri (border, text, input)
✅ Slide-in bölüm animasyonları
✅ Accent line grow animasyonu
✅ Progress bar animasyonu
✅ Hover ripple efektleri
✅ Pulse animasyonları (build button)
✅ Custom title bar (sürüklenebilir)
✅ Modern checkbox/radiobutton/trackbar
✅ Status bar (dinamik)
✅ 5 tam işlevsel bölüm
✅ Build fonksiyonu (async, progress)
✅ Error handling (güzel hata ekranı)

---

## KOD YAPISI ÖNERİSİ

```
Form1.cs
├── HexBackground (Control) - hex grid + particles
├── GlassPanel (Panel) - glassmorphism container
├── AnimatedButton (Button) - ripple + glow
├── GlowTextBox (TextBox) - focus glow
├── Form1
│   ├── BuildTitleBar()
│   ├── BuildSidebar()
│   ├── BuildContent()
│   ├── BuildStatusBar()
│   ├── SectionWebhook()
│   ├── SectionBrowser()
│   ├── SectionForensic()
│   ├── SectionBypass()
│   ├── SectionAdvanced()
│   └── BuildClient()
```

---

**NOT**: Bu GUI bir "Forensic Builder" aracıdır. Kullanıcı webhook URL'i girer, tarama seçeneklerini ayarlar ve "BUILD CLIENT" butonu ile bir EXE oluşturur. Bu EXE hedef bilgisayarda çalıştığında taranan verileri webhook'a gönderir.
