# LFI TARAYICI
---

## Proje Hakkında

**lfi**, Python 3 ile yazılmış, asenkron (asyncio) tabanlı bir Local File Inclusion (LFI) tarama aracıdır. Hedef web uygulamasının `file` parametresi üzerinden LFI açıklıkları tespit etmek için özelleştirilebilir bir wordlist ve etkileşimli mod desteği sunar.

## Özellikler

- Asenkron HTTP istekleri ile yüksek hızda tarama.
- Özelleştirilebilir payload wordlist (`wordlist.txt`).
- Çoklu User-Agent desteği.
- Eşzamanlı istek sayısı ve zaman aşımı ayarı.
- Konsol tabanlı ilerleme çubuğu ve renkli çıktı (Rich, Colorama).
- Bulunan açıklıkları TXT, JSON ve CSV formatlarında loglama.
- Hata yönetimi ve temiz çıkış (signal handling).

## Ön Koşullar

- Python 3.8 veya üzeri
- Aşağıdaki Python paketleri:
  - `aiohttp`
  - `aiofiles`
  - `rich`
  - `colorama`

Kurulum için pip kullanabilirsiniz:

```bash
pip install -r requirements.txt
```

`requirements.txt` içeriği:

```
aiohttp
aiofiles
rich
colorama
```

## Kurulum

1. Depoyu klonlayın:

   ```bash
   git clone https://github.com/vedattascier/lfi.git
   cd lfi
   ```

2. Gerekli paketleri yükleyin:

   ```bash
   pip install -r requirements.txt
   ```


## Kullanım

```bash
python3 lfi.py [OPTIONS]
```

### Parametreler

| Kısa | Uzun             | Açıklama                                                                                         | Varsayılan                      |
|------|------------------|-------------------------------------------------------------------------------------------------|---------------------------------|
| -u   | --url            | Hedef site URL'si (parametreli). Örnek: `http://example.com/page.php?file=`                    | (Zorunlu veya etkileşimli giriş)|
| -w   | --wordlist       | Wordlist dosyasının yolu. Örnek: `wordlist.txt`                                                  | `wordlist.txt` (varsa)          |
| -c   | --concurrency    | Eşzamanlı istek sayısı                                                                          | 50                              |
| -to  | --timeout        | HTTP isteği zaman aşımı (saniye)                                                                | 10                              |
| -k   | --keywords       | Aranacak metin anahtar kelimeleri listesi                                                       | `["root:x", "[fonts]", "MZ"]` |
| -ua  | --useragent      | Kullanılacak User-Agent numarası (1–3 arası)                                                    | 1                               |
| -v   | --verbose        | Detaylı çıktı (istek başına durum bilgisi)                                                      | Kapalı                          |
| -o   | --output         | Sonuçların kaydedileceği dizin                                                                  | `.`                             |

### Etkileşimli Mod

Parametreler verilmezse, aracın konsol arayüzü `URL` ve `wordlist.txt` bilgilerini isteyerek çalışır.

```bash
python3 lfi.py
```

### Örnekler

1. Basit tarama:

   ```bash
   python3 lfi.py -u "http://hedef.com/index.php?file=" -w wordlist.txt
   ```

2. Yüksek paralellik ve kısa timeout ile:

   ```bash
   python3 lfi.py -u "http://hedef.com/page.php?file=" -w wordlist.txt -c 100 -to 5 -v
   ```

3. Özel User-Agent seçimi:

   ```bash
   python3 lfi.py -u "http://hedef.com/?include=" -ua 2
   ```

## Çıktılar ve Log Dosyaları

Tarama tamamlandığında `--output` parametresi ile belirlenen klasörde aşağıdaki dosyalar oluşturulur:

- `bulunan_aciklar_<timestamp>.txt`
- `bulunan_aciklar_<timestamp>.json`
- `bulunan_aciklar_<timestamp>.csv`
- `scanner_debug_<timestamp>.log` (debug ve hata bilgileri)

## Katkıda Bulunanlar

- **Vedat Taşçıer** – Proje Geliştirici ve Tasarımcı

Katkıda bulunmak veya hata bildirmek için lütfen pull request gönderin veya issue açın.

## Lisans

Bu proje MIT lisansı altında sunulmaktadır. Detaylar için [LICENSE](LICENSE) dosyasına bakın.

