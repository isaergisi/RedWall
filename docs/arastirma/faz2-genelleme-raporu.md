# RedWall Faz 2: önceliklendirme, "neden açık" ve genelleme raporu

Tarih: 23 Kasım 2026. Ham veriler: [`benchmarks/realworld/`](../../benchmarks/realworld/).

## Kısa sonuç

- **Önceliklendirme ve açıklama çalışıyor.** Her bulgu 0-100 arası bir risk puanı, P1-P4 kademesi ve
  "neden hâlâ açık" gerekçesiyle raporlanıyor. Hiçbir bulgu gizlenmiyor: satır içinde susturulanlar da ayrı
  bölümde listeleniyor, kullanıcı filtresiyle dışarıda kalanların sayısı yazılıyor. LLM katmanı opsiyonel,
  sırayı en fazla ±8 puan oynatabiliyor ve hiçbir bulguyu silemiyor.
- **Benchmark skoru gerçek dünyaya taşınmıyor.** OWASP BenchmarkPython'da yanlış alarm oranı %3. Daha önce
  hiç bakılmamış 8 gerçek projede, yüksek öncelikli (P1/P2) bulgulardan rastgele seçilen 40 tanesinin yalnızca
  **2'si (%5)** gerçek açık çıktı; 8'i "tasarım gereği" (yetkili kullanıcının zaten sahip olduğu yetenek),
  30'u yanlış alarm. Faz 2 düzeltmelerinden sonra çekilen ikinci, bağımsız 25'lik örneklemde oran **4/25 (%16)**,
  tasarım gereği dahil 7/25 (%28).
- **Bilinen açıkları bulma (recall) orta.** 17 yayımlanmış açık vakasının (CVE/GHSL) 13'ü işaretlendi, ama bunların
  4'ü yalnızca her çağıranın ulaştığı ortak bir `query()` satırında. Açığa özgü satırda yakalanan: **9/17**.
  Bandit 10/17 buluyor, fakat bazı projelerde çok daha fazla bulgu üretiyor (Ray'de 28'e karşı 1033, Open WebUI'da 35'e karşı 273).
- **Aşırı uyumun somut kanıtı bulundu.** Faz 1'in benchmark'tan türetilmiş bir kuralı (`x.startswith(...)`
  kontrolünü temizleyici saymak) Gerapy'deki gerçek bir komut enjeksiyonunu gizliyordu: Faz 0 bu açığı
  buluyordu, Faz 1 kaybetti. Kural düzeltildi ve açık geri geldi; OWASP skoru **değişmedi** (+0,97). Yani
  benchmark aşırı uyumlu ve doğru sürümü birbirinden ayıramıyor. Bu, skorun tek başına başarı ölçütü
  olamayacağını gösteren en net bulgu.

## 1. Faz 2'de yapılanlar

### 1.1 Önem sırasına dizme

Puan dört terimin toplamı, her terimin gerekçesi raporda yazıyor (`redwall/triage/scoring.py`):

| Terim | Değerler |
|---|---|
| Etki (CWE'den) | Kod/komut çalıştırma 50, SQL 42, path 40, sızan sır 40, XXE/SSRF 38, LDAP 36, XPath 34, XSS 30, TLS/debug 22, redirect 20, çerez/zayıf rastgele 15, güven sınırı 12, zayıf özet/geçici dosya 10 |
| Kanıt | Kullanıcı girdisi sink'e kadar izlendi +30, sabit olmayan parçalardan kurulan metin +15, kaynağı bilinmeyen değer 0 (kalıp kuralları için kural güveni: +30/+15/0) |
| Maruziyet | HTTP isteğinden +15, rota fonksiyonu içinde +5, depoya yazılmış sır +10, yerel kullanıcı (`input()`/`argv`) −10 |
| Bağlam | Test/örnek/doküman kodu −20 (listeden çıkmaz) |

Kademeler: P1 80-100, P2 60-79, P3 40-59, P4 0-39. Eşitlikte şiddet, güven ve konum belirler; aynı kod her
seferinde aynı sırayı verir.

### 1.2 Neden hâlâ açık

Her bulgu için motorun kaydettiği gerçeklerden (iz, sink, akış seviyesi, rota bilgisi) üretilen cümleler
(`redwall/triage/explain.py`, İngilizce ve `--lang tr` ile Türkçe):

1. **Kanıt:** "Kullanıcı girdisi 13. satırda `request.args` ile giriyor ve 14. satırda `execute()` çağrısına
   ulaşıyor (izde 4 adım)." Ya da kaynak görülemiyorsa bunu açıkça söyler: "sabit olduğu kanıtlanamadığı için
   açık kalıyor."
2. **Aranan ve bulunamayan önlem:** Motorun gerçekten tanıdığı temizleyiciler listelenir (SQL için parametreli
   sorgu, `int()`, izin listesi). Yalnızca motorun modellediği şeyler için "bulunamadı" denir.
3. **Kısmi önlem:** "`html.escape()` yalnızca xss'e karşı koruyor; bu sink sqli koruması istiyor."
4. **Analizin sınırı:** Çağıranlar, dekoratörler ve form sınıflarının henüz izlenmediği yazılır.
5. **Durum:** Hiçbir inceleyici, LLM veya kanıt adımının bulguyu kapatmadığı ve satırda `redwall: ignore`
   olmadığı belirtilir.
6. **Nasıl kapatılır:** Kuralın düzeltme önerisi.

### 1.3 Hiçbir bulguyu gizlememe

- Satır içi `redwall: ignore` ile susturulan bulgular artık silinmiyor; `suppressed` durumuyla ayrı bölümde,
  SARIF'te standart `suppressions` alanıyla raporlanıyor.
- `--min-severity`/`--min-confidence`/`--rules` filtreleriyle dışarıda kalan bulguların sayısı raporda yazıyor.
- `prioritize()` ve LLM katmanı bulgu sayısının değişmediğini her çalışmada kontrol ediyor (değişirse hata).

### 1.4 Opsiyonel LLM ikinci görüşü

`--llm ollama:<model>` veya `--llm openai:<model>` (llama.cpp, LM Studio, vLLM gibi OpenAI uyumlu sunucular).
Çekirdek hâlâ sıfır bağımlılık (yalnızca `urllib`). Kurallar kodda zorlanıyor:

- Model yalnızca not ekler. Durumu değiştiremez, bulgu silemez.
- Puanı en fazla ±8 oynatabilir ve bunu ancak gösterilen kodda gerçekten var olan satır numaralarını kanıt
  olarak verirse yapabilir. Deterministik puan her zaman yanında görünür.
- Varsayılan olarak yalnızca `localhost`; uzak uç için `--llm-allow-remote` gerekir. Sır bulguları hiç
  gönderilmez, kod diliminde sıra benzeyen değerler maskelenir. Prompt, kodun güvenilmeyen veri olduğunu söyler.
- Zaman aşımı, bozuk JSON veya 3 ardışık hata durumunda deterministik sıra aynen kalır.

**Sınır:** Bu ortamdan Ollama ve Hugging Face'e erişim kapalı olduğu için katman gerçek bir modelle
denenemedi. Doğruluğu yerel sahte HTTP sunucularıyla (iki protokol), kötü niyetli cevaplarla ve hata
senaryolarıyla test edildi; modelin karar kalitesi ölçülmedi.

## 2. Genelleme testi: yöntem

**Hedef seçimi.** Faz 0 ve Faz 1'de hiç bakılmamış 8 proje, her biri yayımlanmış bir açığın bulunduğu sürümde:
Gerapy 0.9.7, pgAdmin 4 7.6, pyLoad (CVE-2023-0297 öncesi commit), calibre-web 0.6.17, Open WebUI 0.3.8,
Langflow 1.2.0, Ray 2.6.3 (dashboard) ve Archery 1.9.0. Toplam 17 vaka: 7 CVE, Gerapy'de aynı güvenlik sürümünde (0.9.8)
düzeltilen 2 komut enjeksiyonu ve GitHub Security Lab'in Archery için yayımladığı 8 SQL injection (GHSL-2022-101..108). Gerçek açık satırları düzeltme commit'inin
diff'inden ya da danışma metninden alındı (`benchmarks/realworld/cves.json`).

**Eşleştirme.** Bir vaka, doğru CWE'ye sahip bir bulgu sink satırına (ya da danışmanın verdiği aralığa)
düşerse yakalanmış sayılır. Archery'de birden fazla açığın aynı genel `query()` satırına ulaştığı durumlarda
o satırdaki isabet "yalnızca ortak sink" olarak ayrı raporlanır, çünkü o bulgu bu danışma hiç olmasa da çıkardı.
Düzeltilmiş sürümü olan projelerde, bulgunun düzeltmeden sonra kaybolup kaybolmadığı da kontrol edildi.

**Kıyas.** Aynı betik Faz 0, Faz 1 ve Faz 2 kaynak ağaçlarını ve Bandit 1.9.4'ü aynı kod üzerinde çalıştırır.
Tekrar üretmek için: `python benchmarks/realworld/run.py --bandit` (GitHub erişimi gerekir).

**Önemli dürüstlük notu.** Aşağıdaki "Faz 2" sütunu, bu testte bulunan hatalar düzeltildikten **sonraki**
sürümdür. Düzeltmeler bu projelere bakılarak yapıldığı için bu sütun artık tam anlamıyla "görülmemiş veri"
değildir. Görülmemiş veri sonucu Faz 1 sütunudur (12/17, 8'i açığa özgü satırda). Düzeltmelerin hepsi genel
kurallardır (belirli proje, dosya veya isim yok) ve OWASP sonucu bit bit aynı kaldı.

## 3. Sonuçlar: bilinen açıklar

| Vaka | Danışma | CWE | Faz 0 | Faz 1 | Faz 2 (sıra) | Bandit |
|---|---|---|---|---|---|---|
| gerapy-configure | CVE-2021-43857 | 78 | orta | orta | orta, #13/14 P2 | yüksek |
| gerapy-clone | 0.9.8'de aynı düzeltme | 78 | yüksek | **kaçırdı** | yüksek, #1/14 P1 | yüksek |
| gerapy-parse | 0.9.8'de aynı düzeltme | 78 | yüksek | yüksek | yüksek, #2/14 P1 | yüksek |
| pgadmin-binary-path | CVE-2023-5002 | 78 | yüksek | yüksek | yüksek, #1/556 P1 | yüksek |
| pyload-cnl-eval-js | CVE-2023-0297 | 94 | kaçırdı | kaçırdı | kaçırdı | kaçırdı |
| calibreweb-cover-ssrf | CVE-2022-0939 | 918 | kaçırdı | kaçırdı | kaçırdı | kaçırdı |
| openwebui-model-upload | CVE-2024-7034 (*) | 22 | yüksek | yüksek | yüksek, #1/35 P1 | kaçırdı |
| langflow-validate-exec | CVE-2025-3248 | 94 | düşük | düşük | düşük, #17/32 P3 | kaçırdı |
| ray-cpu-profile | CVE-2023-6019 | 78 | kaçırdı | kaçırdı | kaçırdı | düşük |
| archery-101 | GHSL-2022-101 | 89 | orta | orta | orta, #30/31 P3 | düşük |
| archery-102 | GHSL-2022-102 | 89 | ortak sink | ortak sink | ortak sink, #19/31 P3 | düşük |
| archery-103 | GHSL-2022-103 | 89 | orta | orta | orta, #18/31 P3 | kaçırdı |
| archery-104 | GHSL-2022-104 | 89 | kaçırdı | kaçırdı | kaçırdı | düşük |
| archery-105 | GHSL-2022-105 | 89 | ortak sink | ortak sink | ortak sink, #16/31 P3 | düşük |
| archery-106 | GHSL-2022-106 | 89 | ortak sink | ortak sink | ortak sink, #16/31 P3 | düşük |
| archery-107 | GHSL-2022-107 | 89 | orta | orta | orta, #26/31 P3 | kaçırdı |
| archery-108 | GHSL-2022-108 | 89 | ortak sink | ortak sink | ortak sink, #16/31 P3 | kaçırdı |
| **Toplam** | | | **13/17 (9)** | **12/17 (8)** | **13/17 (9)** | **10/17 (10)** |

Parantez içi: açığa özgü satırda yakalananlar. (*) CVE-2024-7034, uç yalnızca yöneticiye açık olduğu için
Open WebUI ve CVE'yi veren kurum tarafından reddedildi; kod düzeyindeki path traversal gerçek, etkisi tartışmalı.

Düzeltilmiş sürümler: Gerapy (3 vaka) ve pgAdmin bulguları düzeltmeden sonra kayboldu, yani düzeltmeyi
"gördüler". Langflow bulgusu 1.3.0'da da duruyor; bu doğru, çünkü düzeltme `exec` çağrısını değil uca kimlik
doğrulamayı ekledi.

Bulgu hacmi (Python motoru, Faz 2): Gerapy 14, pgAdmin 556 (498'i P4: çoğu MD5/SHA-1 ve rastgele sayı),
pyLoad 35, calibre-web 22, Open WebUI 35, Langflow 32, Ray 28, Archery 31. Bandit aynı kapsamlarda
11, 630, 143, 22, 273, 44, 1033 ve 133 bulgu verdi. En büyük proje (pgAdmin) 5 saniyede tarandı.

**Kasıtlı açıklı ama görülmemiş uygulamalar.** DSVW (tek dosya, `http.server`): RedWall'un kapsadığı
kategorilerdeki 14 açıktan 8'i bulundu (3 SQLi, pickle, komut, XXE, `exec`, zayıf oturum kimliği), 8 bulgunun
8'i gerçek. Kaçırılan 6'sı (path traversal ×2, SSRF, XPath, açık yönlendirme, yansıyan XSS) aynı nedenden:
kaynak `self.path`, RedWall bunu kullanıcı girdisi olarak tanımıyor. vulpy "bad" sürümünde 10 bulgunun
4'ü gerçek açık (3 SQLi, zayıf rastgele API anahtarı), 4'ü gerçek yapılandırma sorunu (2 `debug=True`, 2 Secure
bayraksız çerez), 2'si yanlış alarm (yerel bir CLI'nın `argv`'si, sabitlerden kurulan SQL). "good" sürümünde 7 bulgu: 1 SQLi gerçek (sürüm bitmemiş), 4 yapılandırma, 2 yanlış alarm.

## 4. Sonuçlar: gerçek kodda kesinlik

Etiket ölçütü (`benchmarks/realworld/results/precision-labels.json`, her etiketin bir satırlık gerekçesi var):

- **Gerçek (TP):** saldırganın verisi sink'e ulaşıyor ve özelliğin amaçladığından fazlasını veriyor.
- **Tasarım gereği:** akış gerçek ama yetkili kullanıcının zaten sahip olduğu yetenek (yöneticinin dosya
  seçicisi, SQL istemcisinin kullanıcının SQL'ini çalıştırması, zaten Python çalıştırabilen yönetici).
- **Yanlış alarm (FP):** iddia yanlış (saldırgan verisi yok, sink anlamı yanlış, RedWall'un göremediği doğrulama var).

| Örneklem | Ne zaman | Gerçek | Tasarım gereği | Yanlış alarm | Kesinlik (katı / geniş) |
|---|---|---|---|---|---|
| 1: P1/P2'den 40 (havuz 238) | Faz 2 motor düzeltmelerinden önce | 2 | 8 | 30 | **%5 / %25** |
| 2: P1/P2'den 25 (havuz 121) | Düzeltmelerden sonra, bağımsız | 4 | 3 | 18 | **%16 / %28** |

Örneklem 1'deki 30 yanlış alarmın 17'si düzeltmelerden sonra hiç raporlanmıyor ve hiçbir gerçek ya da tasarım
gereği bulgu kaybolmadı (bu örneklem içi bir ölçüm). Örneklem 2'deki 18 yanlış alarmın 8'i (sunucu tarafı
oturumdan `pickle.loads`) kanıt puanı düzeltmesiyle P3'e indi. Bu son düzeltme örneklem 2'ye bakılarak
yapıldığı için onun kesinliğini artık "temiz" ölçmüyor; temiz sayı yukarıdaki %16.

Yanlış alarmların sınıfları (iki örneklem, 48 FP):

| Sınıf | Adet | Durum |
|---|---|---|
| Rota fonksiyonunun döndürdüğü yanıt nesnesi HTML sanıldı (`make_json_response`, aiohttp `Response`) | 20 | Çoğu düzeltildi: keyfi çağrı sonucu artık HTML gövdesi sayılmıyor. Değişkene atanıp döndürülen yanıt nesneleri hâlâ alarm veriyor |
| Uygulamanın kendi yazdığı veriden `pickle.loads` (sunucu tarafı oturum, süreç tablosu) | 11 | Kaynak bilinmiyorsa kanıt 0 puan: P2 → P3 |
| Görülemeyen doğrulama (ORM araması, `can_rollback`, yardımcı izin kontrolü, DB'de var olma) | 5 | Açık: çağrılar arası analiz gerekiyor (Faz 3) |
| Sürecin kendi `sys.argv[0]`'ı | 3 | Açık: `argv[0]` kaynak sayılmamalı |
| Sabit ana makineye ya da `reverse()` ile yönlendirme / istek | 3 | Açık |
| Django `QuerySet.exists()` dosya sistemi sanıldı | 2 | Düzeltildi |
| `Markup(x).unescape()` XSS sanıldı | 2 | Açık |
| Diğer (çağrılmayan ölü kod, AST'den gelen tanımlayıcı) | 2 | Açık |

## 5. Aşırı uyum (overfitting) bulguları

Benchmark kalıplarına bakılarak yazılmış Faz 1 kurallarının dört yerde gerçek kodda yanlış davrandığı görüldü.
Hepsi genel olarak düzeltildi, her biri için Faz 1'de başarısız olan bir test eklendi:

1. **Önek/sonek kontrolü temizleyici sayılıyordu.** `if not x.startswith("http"): return` sonrasında `x`
   SQL, komut, XSS gibi tüm türler için temiz kabul ediliyordu; `endswith(".py")` ve çapasız `re.match` ise her
   tür için. `"http://x; id"` "http" ile başlar, `"../../a.py"` ".py" ile biter. Bu kural Gerapy'deki gerçek
   komut enjeksiyonunu gizliyordu. Benchmark'taki asıl kalıp (değerin tek tırnaklı bir metin olduğunu doğrulayan
   üçlü kontrol) artık ayrı ve dar bir kural; önek kontrolü yalnızca normalleştirilmiş yolda ve yalnızca path için
   geçerli; `re.match` yalnızca `$`/`\Z` ile çapalı ve `.*` içermeyen desenle; `isascii()` hiçbir şey temizlemiyor.
2. **Rota dönüşü XSS'i.** Benchmark'ta rota hep bir metin döndürüyor; gerçek uygulamalar yanıt nesnesi döndürüyor.
3. **`.exists()` gibi pathlib metotları** yalnızca isimden eşleniyordu.
4. **Kanıt puanı** kaynağı bilinmeyen `pickle.loads` için "sabit olmayan metin" diyordu; hem puan hem açıklama yanlıştı.

Dördü de düzeltildikten sonra OWASP BenchmarkPython sonucu kategori kategori aynı (+0,97). Bu, benchmark'ın bu
hataların hiçbirini ölçemediğini, yani +0,97'nin genelleme hakkında bilgi vermediğini gösteriyor.

## 6. Kaçırılan açıkların kök nedenleri

| Vaka | Neden |
|---|---|
| calibre-web SSRF, Archery 104 | Kaynak bir dosyada, sink başka dosyadaki yardımcıda (çağrılar arası analiz yok) |
| Ray CVE-2023-6019 | `asyncio.create_subprocess_shell` sink listesinde yok, akış da sınıf metodundan geçiyor |
| pyLoad CVE-2023-0297 | `js2py.eval_js` kod çalıştırma sink'i olarak tanımlı değil |
| DSVW'deki 6 açık | `BaseHTTPRequestHandler.path` kaynak olarak tanımlı değil |
| Langflow, Gerapy-configure, Archery (düşük/orta) | FastAPI gövde modeli ve Django URL parametresi kaynak değil; bulgu yalnızca "kaynağı bilinmeyen" olarak çıkıyor ve P3'e düşüyor |

## 7. Sıralamanın başarımı

Yakalanan 13 vakanın 4'ü kendi projesinde **1. veya 2. sırada** (Gerapy ×2, pgAdmin'de 556 bulgu içinde 1.,
Open WebUI'da 1.). Zayıf taraf Archery: 8 SQL injection'ın tamamı P3'te ve listenin alt yarısında, çünkü kaynak
başka dosyada kaldığı için kanıt "sabit olmayan metin" düzeyinde. Üstlerinde gerçek bir SQL injection
(`instance_account.py`) ama aynı zamanda ORM'le doğrulanan dosya yolları da var. Yani sıralama, kanıtın gücünü
doğru yansıtıyor ama kanıtı toplayan motor çağrılar arası akışı görmediği için gerçek açıkları aşağıda
bırakabiliyor. Bu bir sıralama değil, kapsama sorunu.

## 8. Tarafsızlık ve sınırlar

- Etiketleri tek bir inceleyici kodu okuyarak verdi; ikinci bir göz yok. Gerekçeler kayıtlı, itiraz edilebilir.
- 17 vaka ve 65 etiketli bulgu küçük örneklemler; yüzdeler kaba tahmindir (örneğin %16'nın güven aralığı geniş).
- Sonuçlar yalnızca Python motoru için; JS/TS ve sır motoru bu testte ölçülmedi.
- Düzeltmeler bu projelere bakılarak yapıldı. Bir sonraki ölçüm, bu dosyaya hiç girmemiş yeni projelerle
  yapılmalı (`cves.json` bundan sonra "görülmüş" sayılmalı).
- LLM katmanının karar kalitesi ölçülmedi (ortamda model yok).

## 9. Önerilen sonraki adımlar (Faz 3)

1. Çağrılar arası (en azından tek seviye) argüman akışı: kaçırılan ve P3'te kalan açıkların çoğunun kaynağı bu.
2. Kaynak/sink bilgisi genişletme: aiohttp `req.query`/`match_info`, Django URL parametreleri, FastAPI gövde
   modelleri, `http.server` `self.path`; `asyncio.create_subprocess_shell`, `js2py.eval_js`.
3. Yanıt nesnesi takibi: değişkene atanmış `Response`/`JsonResponse` da HTML gövdesi sayılmamalı.
4. LLM katmanını gerçek bir yerel modelle bu 65 etiketli bulgu üzerinde ölçmek: ölçüt "kaç yanlış alarm aşağı
   indi" değil, "hiçbir gerçek açık aşağı inmedi mi" olmalı.
5. Bu raporun etiketlerini ikinci bir kişiye kör olarak yeniden etiketletmek.
