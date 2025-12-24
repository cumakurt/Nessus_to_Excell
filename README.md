# Nessus to Excel Converter

Professional Python CLI tool to convert Nessus XML scan results into comprehensive Excel reports with advanced analytics, risk scoring, and compliance checking.

## Features

- 📊 **Professional Excel Reports**: Multi-sheet reports with charts, formatting, and color coding
- 🔍 **Risk Scoring**: Organization-specific risk score calculation based on CVSS, port, protocol, exploit status, and exposure
- 🌐 **Exposure Detection**: Automatic Internal/External classification using RFC1918 IP detection
- 🔒 **PCI-DSS Compliance**: Automated PCI-DSS compliance checking with pass/fail status
- 📈 **CVE Analysis**: Normalized CVE grouping and analysis
- 🎨 **Visual Analytics**: Charts and graphs for vulnerability distribution, top hosts, and exposure
- ⚡ **Performance**: Progress bars and optimized processing for large scan files

## Requirements

- Python 3.10+
- Required packages: `pandas`, `openpyxl`, `tqdm`

## Installation

### Quick Start

Simply download `nessus_to_excell.py` and install dependencies:

```bash
pip install pandas openpyxl tqdm
```

That's it! The script is standalone and requires no additional configuration files.

### From GitHub

```bash
# Clone the repository
git clone https://github.com/cumakurt/Nessus_to_Excell.git
cd nessus_to_excell

# Install dependencies
pip install -r requirements.txt
```

## Usage

### Basic Usage

```bash
python nessus_to_excell.py scan.nessus -o report.xlsx
```

### Multiple Input Files

```bash
python nessus_to_excell.py scan1.nessus scan2.nessus -o combined_report.xlsx
```

### Include Info Severity

```bash
python nessus_to_excell.py scan.nessus -o report.xlsx --include-info
```

### Verbose Output

```bash
python nessus_to_excell.py scan.nessus -o report.xlsx --verbose
```

### Save Logs to File

```bash
python nessus_to_excell.py scan.nessus -o report.xlsx --log-file scan.log
```

## Command Line Options

```
positional arguments:
  input_files           One or more .nessus files to process

optional arguments:
  -h, --help           Show help message and exit
  -o OUTPUT, --output OUTPUT
                       Output Excel file path (default: nessus_report.xlsx)
  -v, --verbose        Enable verbose logging
  --log-file LOG_FILE  Path to log file (optional)
  --no-progress        Disable progress bar
  --include-info       Include Info (severity 0) vulnerabilities in the report
```

## Excel Report Structure

The generated Excel report contains the following sheets:

1. **Summary** - Overview with statistics, risk scores, and charts
2. **CVE Summary** - Normalized CVE grouping with affected hosts and vulnerabilities
3. **PCI-DSS Compliance** - PCI-DSS compliance status with pass/fail indicators
4. **Critical** - Critical severity vulnerabilities (grouped by plugin)
5. **High** - High severity vulnerabilities (grouped by plugin)
6. **Medium** - Medium severity vulnerabilities (grouped by plugin)
7. **Low** - Low severity vulnerabilities (grouped by plugin)
8. **All Vulnerabilities** - Complete list of all vulnerabilities

## Risk Score Calculation

The risk score (0-100) is calculated using:

- **CVSS Base Score** (0-10)
- **Port Risk Multiplier** (high-risk ports: 21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 1433, 3306, 3389, 5432, 8080)
- **Protocol Risk** (TCP = 1.1x multiplier)
- **Exploit Status** (Available = 1.5x, Possibly = 1.2x)
- **Exposure** (External = 1.3x multiplier)

## PCI-DSS Compliance Rules

A vulnerability fails PCI-DSS compliance if:

- Severity is Critical
- High severity with External exposure
- High severity with available exploit
- CVSS >= 7.0 with External exposure
- CVSS >= 9.0
- Risk Score >= 80
- High-risk port with External exposure

## Exposure Classification

IP addresses are automatically classified as:

- **Internal**: RFC1918 private addresses (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
- **External**: All other IP addresses

## Examples

### Single File Processing

```bash
python nessus_to_excell.py network_scan.nessus -o network_report.xlsx
```

### Batch Processing

```bash
python nessus_to_excell.py *.nessus -o combined_report.xlsx
```

### With Verbose Logging

```bash
python nessus_to_excell.py scan.nessus -o report.xlsx --verbose --log-file scan.log
```

## Output Format

The Excel report includes:

- ✅ Professional formatting with color coding
- 📊 Charts and graphs for data visualization
- 🎨 Conditional formatting based on severity and risk
- 📋 Grouped vulnerabilities by plugin
- 🔍 Detailed vulnerability information
- 📈 Risk score statistics
- 🔒 PCI-DSS compliance status

## License

This project is licensed under the GNU General Public License v3.0 (GPL-3.0).

See the [LICENSE](LICENSE) file for details.

## Author

**Developed by:** Cuma KURT  
**Email:** cumakurt@gmail.com  
**LinkedIn:** https://www.linkedin.com/in/cuma-kurt-34414917/

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Support

For issues, questions, or contributions, please open an issue on GitHub.

---

# Nessus için  Excel Dönüştürücü

Nessus XML tarama sonuçlarını gelişmiş analitik, risk skorlama ve uyumluluk kontrolü içeren kapsamlı Excel raporlarına dönüştüren profesyonel Python CLI aracı.

## Özellikler

- 📊 **Profesyonel Excel Raporları**: Grafikler, formatlama ve renk kodlaması içeren çok sayfalı raporlar
- 🔍 **Risk Skorlama**: CVSS, port, protokol, exploit durumu ve exposure'a dayalı kuruma özel risk skoru hesaplama
- 🌐 **Exposure Tespiti**: RFC1918 IP tespiti kullanarak otomatik Internal/External sınıflandırma
- 🔒 **PCI-DSS Uyumluluğu**: Pass/fail durumu ile otomatik PCI-DSS uyumluluk kontrolü
- 📈 **CVE Analizi**: Normalize edilmiş CVE gruplandırma ve analizi
- 🎨 **Görsel Analitik**: Güvenlik açığı dağılımı, en çok etkilenen hostlar ve exposure için grafikler
- ⚡ **Performans**: Büyük tarama dosyaları için progress bar'lar ve optimize edilmiş işleme

## Gereksinimler

- Python 3.10+
- Gerekli paketler: `pandas`, `openpyxl`, `tqdm`

## Kurulum

### Hızlı Başlangıç

Sadece `nessus_to_excell.py` dosyasını indirin ve bağımlılıkları kurun:

```bash
pip install pandas openpyxl tqdm
```

Bu kadar! Script bağımsızdır ve ek konfigürasyon dosyası gerektirmez.

### GitHub'dan

```bash
# Depoyu klonlayın
git clone https://github.com/cumakurt/Nessus_to_Excell.git
cd nessus_to_excell

# Bağımlılıkları kurun
pip install -r requirements.txt
```

## Kullanım

### Temel Kullanım

```bash
python nessus_to_excell.py scan.nessus -o report.xlsx
```

### Birden Fazla Dosya

```bash
python nessus_to_excell.py scan1.nessus scan2.nessus -o combined_report.xlsx
```

### Info Severity Dahil Etme

```bash
python nessus_to_excell.py scan.nessus -o report.xlsx --include-info
```

### Detaylı Çıktı

```bash
python nessus_to_excell.py scan.nessus -o report.xlsx --verbose
```

### Log Dosyasına Kaydetme

```bash
python nessus_to_excell.py scan.nessus -o report.xlsx --log-file scan.log
```

## Komut Satırı Seçenekleri

```
konum argümanları:
  input_files           İşlenecek bir veya daha fazla .nessus dosyası

opsiyonel argümanlar:
  -h, --help           Yardım mesajını göster ve çık
  -o OUTPUT, --output OUTPUT
                       Çıktı Excel dosya yolu (varsayılan: nessus_report.xlsx)
  -v, --verbose        Detaylı loglama etkinleştir
  --log-file LOG_FILE  Log dosyası yolu (opsiyonel)
  --no-progress        Progress bar'ı devre dışı bırak
  --include-info       Info (severity 0) güvenlik açıklarını rapora dahil et
```

## Excel Rapor Yapısı

Oluşturulan Excel raporu aşağıdaki sayfaları içerir:

1. **Summary** - İstatistikler, risk skorları ve grafiklerle genel bakış
2. **CVE Summary** - Etkilenen hostlar ve güvenlik açıklarıyla normalize edilmiş CVE gruplandırma
3. **PCI-DSS Compliance** - Pass/fail göstergeleriyle PCI-DSS uyumluluk durumu
4. **Critical** - Critical severity güvenlik açıkları (plugin'e göre gruplandırılmış)
5. **High** - High severity güvenlik açıkları (plugin'e göre gruplandırılmış)
6. **Medium** - Medium severity güvenlik açıkları (plugin'e göre gruplandırılmış)
7. **Low** - Low severity güvenlik açıkları (plugin'e göre gruplandırılmış)
8. **All Vulnerabilities** - Tüm güvenlik açıklarının tam listesi

## Risk Skoru Hesaplama

Risk skoru (0-100) şu faktörler kullanılarak hesaplanır:

- **CVSS Base Score** (0-10)
- **Port Risk Çarpanı** (yüksek riskli portlar: 21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 1433, 3306, 3389, 5432, 8080)
- **Protokol Riski** (TCP = 1.1x çarpan)
- **Exploit Durumu** (Mevcut = 1.5x, Muhtemelen = 1.2x)
- **Exposure** (External = 1.3x çarpan)

## PCI-DSS Uyumluluk Kuralları

Bir güvenlik açığı şu durumlarda PCI-DSS uyumluluğunu başarısız kılar:

- Severity Critical ise
- High severity + External exposure
- High severity + mevcut exploit
- CVSS >= 7.0 + External exposure
- CVSS >= 9.0
- Risk Skoru >= 80
- Yüksek riskli port + External exposure

## Exposure Sınıflandırması

IP adresleri otomatik olarak şu şekilde sınıflandırılır:

- **Internal**: RFC1918 özel adresler (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
- **External**: Diğer tüm IP adresleri

## Örnekler

### Tek Dosya İşleme

```bash
python nessus_to_excell.py network_scan.nessus -o network_report.xlsx
```

### Toplu İşleme

```bash
python nessus_to_excell.py *.nessus -o combined_report.xlsx
```

### Detaylı Loglama ile

```bash
python nessus_to_excell.py scan.nessus -o report.xlsx --verbose --log-file scan.log
```

## Çıktı Formatı

Excel raporu şunları içerir:

- ✅ Renk kodlaması ile profesyonel formatlama
- 📊 Veri görselleştirme için grafikler ve çizelgeler
- 🎨 Severity ve risk'e dayalı koşullu formatlama
- 📋 Plugin'e göre gruplandırılmış güvenlik açıkları
- 🔍 Detaylı güvenlik açığı bilgileri
- 📈 Risk skoru istatistikleri
- 🔒 PCI-DSS uyumluluk durumu

## Lisans

Bu proje GNU General Public License v3.0 (GPL-3.0) altında lisanslanmıştır.

Detaylar için [LICENSE](LICENSE) dosyasına bakın.

## Geliştirici

**Geliştiren:** Cuma KURT  
**E-posta:** cumakurt@gmail.com  
**LinkedIn:** https://www.linkedin.com/in/cuma-kurt-34414917/

## Katkıda Bulunma

Katkılarınız memnuniyetle karşılanır! Lütfen bir Pull Request göndermekten çekinmeyin.

## Destek

Sorunlar, sorular veya katkılar için lütfen GitHub'da bir issue açın.

## Dosya Yapısı

```
nessus_to_excell/
├── nessus_to_excell.py    # Bağımsız script (hepsi bir arada)
├── requirements.txt        # Python bağımlılıkları
├── README.md              # Bu dosya
├── LICENSE                # GPL-3.0 Lisansı
└── .gitignore            # Git ignore kuralları
```

**Not**: Script tamamen bağımsızdır. Tüm konfigürasyon ve logging kodu `nessus_to_excell.py` içine gömülüdür. Script'i çalıştırmak için ek dosya gerekmez.
