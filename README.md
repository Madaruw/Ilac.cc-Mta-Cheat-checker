<div align="center">

# ⛧ ilac.cc — MTA Anti-Cheat & Forensic Suite ⛧

**Windows Tabanlı Anti-Forensic Tespit ve Hile Analiz Motoru**

*MTA sunucuları için geliştirilmiş; sistem seviyesindeki dosya izlerini, bellek enjeksiyonlarını ve anti-forensic gizleme girişimlerini yakalayan adli bilişim aracı.*

<br>

> ⚠️ **UYARI: KULLANMADAN ÖNCE VİDEOYU İZLEYİN**
>
> [![Kullanım Videosu](https://img.youtube.com/vi/YOUTUBE_VIDEO_ID/maxresdefault.jpg)](YOUTUBE_LINKI_BURAYA)
>
> *Kurulum ve kullanım adımlarını eksiksiz uygulamak için yukarıdaki görsele tıklayarak rehber videoyu izleyin.*

---

</div>

<br>

## 🗡️ Mimari ve Çalışma Mantığı

`ilac.cc`, hilecilerin sistemde bıraktığı izleri silme (**anti-forensic**) çabalarını tespit etmek üzerine kurgulanmıştır. 

Sistemde yapılan **USN Journal sıfırlama**, **Prefetch temizliği**, **Event Log boşaltma**, **BAM tahrifatı** ve **DMA (Direct Memory Access) donanım kullanımı** gibi eylemler doğrudan yüksek risk olarak puanlanır.

<br>

### 💀 Temel Bileşenler

* **Builder (Yönetim Paneli):** Sunucu yöneticisinin tarama modüllerini, Discord Webhook adresini ve Groq AI entegrasyonunu konfigüre ettiği masaüstü arayüzü.
* **Client (Taratıcı Motor):** Builder tarafından `dotnet publish` ile tek dosya (`.exe`) olarak derlenen, hedef sistemde admin yetkisiyle adli bilişim taraması yapan istemci.

<br>

---

## 👁️‍🗨️ Çalışma Akışı

<div align="center">

<table>
  <tr>
    <td align="center" width="220">
      <b>1. Konfigürasyon</b><br>
      <code>Ilac.Checker.exe</code><br>
      <small>Builder Arayüzü</small>
    </td>
    <td align="center">➔</td>
    <td align="center" width="220">
      <b>2. Derleme</b><br>
      <code>Ilac.Client.exe</code><br>
      <small>Self-Contained Exe</small>
    </td>
    <td align="center">➔</td>
    <td align="center" width="220">
      <b>3. Taramalar</b><br>
      <code>20+ Forensic Scanner</code><br>
      <small>Native API & YARA</small>
    </td>
  </tr>
</table>

<br>

<table>
  <tr>
    <td align="center" width="300">
      <b>4. Puanlama & AI Analizi</b><br>
      <code>ScoringService & Groq Engine</code>
    </td>
    <td align="center">➔</td>
    <td align="center" width="300">
      <b>5. Raporlama</b><br>
      <code>Discord Webhook</code>
    </td>
  </tr>
</table>

</div>

<br>

---

## ⚡ Forensic Taramaları ve Kapsam

İşletim sisteminin derinliklerindeki izleri ortaya çıkarmak için 20'den fazla bağımsız tarama modülü çalıştırılır.

<br>

### 🩸 Derin Sistem Taramaları

| Tarayıcı Modülü | Analiz Edilen Alan / Teknik | Tespit Edilen Şüpheli Aktivite |
| :--- | :--- | :--- |
| **USN Journal** | `FSCTL_ENUM_USN_DATA` Win32 API | Son silinen/oluşturulan dosyalar, Journal sıfırlama izleri |
| **Prefetch (`.pf`)** | `C:\Windows\Prefetch` & MAM Yapısı | Son çalıştırılan `.exe`'ler, çalışma sayıları ve zaman damgaları |
| **BAM / DAM** | `SYSTEM\... \bam\State\UserSettings` | Background Activity Moderator kayıt tahrifatı ve gizli executable'lar |
| **AmCache & ShimCache** | `Amcache.hve` & `AppCompatCache` | Silinmiş olsa dahi geçmişte çalıştırılmış binary izleri |
| **Loaded Modules** | `EnumProcessModulesEx` & PE Header | Süreçlere enjekte edilmiş unmapped/unsigned DLL modülleri |
| **YARA / Binary** | Bellek içi YARA Pattern Matching | Bilinen hile kod blokları, byte dizilimleri ve signature match |
| **Kernel & Drivers** | `EnumDeviceDrivers` & Signature Check | İmzasız sürücüler, vulnerable driver (BYOVD) ve DMA donanımları |
| **Event Logs** | `System`, `Security`, `PowerShell` | Log temizleme eylemleri (Event ID 1102), Script Block Logging |

<br>

### 🌐 Diğer İzleme Noktaları

* **Browser Forensics:** Chrome, Edge, Firefox, Opera GX, Brave ve Vivaldi SQLite veritabanı okuması. Hile arama terimleri ve silinmiş geçmiş.
* **Network & Persistence:** Hosts dosyası yönlendirmeleri, şüpheli IP/Domain bağlantıları, Scheduled Tasks (Görev Zamanlayıcı) ve servis injection'ları.
* **USB & Virtual Media:** USB Storage (`USBSTOR`) bağlantı geçmişi, taşınabilir bellekten çalıştırılan dosyalar ve VHD/ISO bağlama izleri.
* **Execution Artifacts:** Jumplists, PcaClient (Program Uyumluluk Asistanı), Shellbags ve ShimEngine logları.

<br>

---

## ⚖️ Puanlama Mantığı (`ScoringService`)

Her bulgu eşit ağırlığa sahip değildir. False-positive oranını sıfıra yakın tutmak için **ağırlıklı skorlama** kullanılır.

<br>

| Durum | Skor Aralığı | Açıklama |
| :--- | :--- | :--- |
| 🔴 **HİLE VAR** | `Skor >= 80` | Kritik DLL Enjeksiyonu, YARA Signature Eşleşmesi, Unsigned Driver |
| 🟡 **ŞÜPHELİ** | `Skor 40 - 79` | USN Journal / Prefetch Temizliği, Şüpheli Registry veya Log Silme |
| 🟢 **HİLE YOK** | `Skor < 40` | Temiz Sistem / Herhangi bir kritik bulguya rastlanmadı |

<br>

---

## 🖤 AI Destekli Analiz (Groq LLM)

Tarama verileri `GroqService` üzerinden yapay zekaya aktarılır. AI, adli bilişim kanıtlarını çapraz sorgulayarak Discord kanalına kısa bir karar raporu yollar.

```json
{
  "status": "HILE VAR",
  "detected_tool": "Internal MTA Cheat / Injector",
  "summary": "USN Journal'ın yakın zamanda temizlendiği ve 'gta_sa.exe' sürecine imzasız bir modül enjekte edildiği tespit edilmiştir."
}
⚙️ Groq API Kurulumu
Groq Console üzerinden bir API Key oluşturun.

Builder uygulamasında Advanced sekmesine geçip Key'i kaydedin.

Önemli: API Key ve Webhook URL'si client üretilirken compile-time injection ile doğrudan .exe içerisine gömülür. Target bilgisayarda ek bir yapılandırma gerekmez.

C#
// Model Yapılandırması (Ilac.Shared/Services/GroqService.cs)
private static readonly string[] Models =
{
    "groq/compound",
    "groq/compound-mini"
};
🕷️ Derleme & Proje Yapısı
Derleme işlemi için sistemde .NET 9.0 SDK kurulu olmalıdır.

Plaintext
ilac-checker/
├── Ilac.Checker/          # Builder (WinForms UI)
├── Ilac.Shared/           # Çekirdek Kütüphane (Scanner Engine, Native API & YARA)
└── Ilac.Client/           # Reference Client (Target Executable Source)
🩸 Production Single-File Build
Bash
dotnet publish Ilac.Checker\Ilac.Checker.csproj \
  -c Release \
  -o "./BuildOutput" \
  --self-contained true \
  -r win-x64 \
  /p:PublishSingleFile=true \
  /p:IncludeNativeLibrariesForSelfExtract=true \
  /p:DebugType=none \
  /p:DebugSymbols=false
Not: Builder'ın hedef client derleyebilmesi için Ilac.Shared klasörünün Ilac.Checker.exe ile aynı dizinde durması zorunludur.

🕯️ Kullanılan Teknolojiler
C# / .NET 9.0 — Yüksek performanslı sistem ve bellek tarama motoru.
Builder makinesinde .NET 9 SDK kurulu olmalı

Win32 Native API (P/Invoke) — Kernel seviyesi USN Journal, Handles ve Process Modules erişimi.

YARA Engine — Binary pattern matching ve imza taraması.

Discord Webhook & Groq LLM — Otomatik raporlama ve adli bilişim analizi.

📜 Yasal Uyarı
Bu yazılım yalnızca yöneticisi olduğunuz MTA sunucularında adil oyun ortamı sağlamak amacıyla geliştirilmiştir. Kullanıcı bilgisi ve izni dışında çalıştırılması veya yetkisiz veri toplanması durumunda tüm yasal sorumluluk uygulayıcıya aittir.
