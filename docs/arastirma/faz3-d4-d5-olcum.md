# Faz 3, D4-D5: çağrı çözümleme (CallResolver) ve Summary v2

## Kısa sonuç

- **Held-out'ta iyileşme yok.** 13 görülmemiş vakada D4 ve D5 sonrası bütün seviyeler D3 ile aynı. Açık
  seviyesinde precision, recall ve F1 0,50 / 0,31 / 0,38; tam satırda 0,50 / 0,31 / 0,38; akışta
  0,60 / 0,23 / 0,33. Aynı vakalar bulunuyor, aynı vakalar kaçıyor.
- **Dev setinde (görülen) belirgin iyileşme var.** Açık seviyesinde recall 0,77'den 0,88'e, tam satırda
  0,53'ten 0,71'e, akışta 0,18'den 0,47'ye çıktı. Precision 0,90-0,94 bandında kaldı. Yeni yakalanan iki vaka
  var: calibre-web kapak SSRF'i ve Archery GHSL-2022-104.
- **Sentetik sette (görülen, biz yazdık) tam satır recall'ü 0,50'den 1,00'e çıktı.** Bu set D5 geliştirilirken
  regresyon seti olarak kullanıldı. Genelleme ölçüsü değil.
- **D5 bulgu sayısını artırıyor.** Held-out'ta 347'den 447'ye (+100), P1 öncelikli bulgular 52'den 152'ye çıktı.
  Bu 100 ek bulgu düzeltilmiş sürümlerde de duruyor (düzeltilmiş ağaçlarda 345 → 445). Yani danışma
  kayıtlarındaki açıklarla ilgili değiller. Bir kısmı gerçek olabilir, ama vaka düzeyinde ölçemediğimiz için
  bilinmiyor. Dev'deki örneklere göre önemli bir kısmının kaynağı aşırı geniş kaynak tanımı (aşağıda).
- **D4 tek başına hiçbir metriği değiştirmedi.** D4 altyapı; etkisi D5 ile görünüyor.
- **Süre:** pgAdmin taraması ortalama 6,6 s'den 8,3 s'ye çıktı (yaklaşık %25). Bellek 218 MB'den 221 MB'ye.

Benchmark'a özel kural eklenmedi. Held-out'taki 6 kayıp yüksek öncelikli bulguya bakılmadı. Held-out yalnızca
D5'in son hâli için bir kez ölçüldü ve sonrasında kod değiştirilmedi.

## Önce ve sonra

"D3" PR #4'ün head'i (`0500fe7`), "D4" PR #5'in head'i, "D5" bu dalın son hâli. Seviyeler D1-D3 raporundakiyle
aynı: dosya, açık, tam satır (danışmaya özgü sink satırı, exact-line accuracy) ve akış (tam satır ve iz GT kaynağından
başlıyor). TP ve FN açık sürümden, FP ve TN düzeltilmiş sürümden geliyor.

### Dev seti (görülen), 17 vaka

| Seviye | D3 = D4 TP/FN/FP/TN | D3 = D4 P / R / F1 | D5 TP/FN/FP/TN | D5 P / R / F1 |
|---|---|---|---|---|
| dosya | 14/3/1/6 | 0,93 / 0,82 / 0,88 | 15/2/1/6 | 0,94 / 0,88 / 0,91 |
| açık | 13/4/1/6 | 0,93 / 0,77 / 0,84 | 15/2/1/6 | 0,94 / 0,88 / 0,91 |
| tam satır | 9/8/1/6 | 0,90 / 0,53 / 0,67 | 12/5/1/6 | 0,92 / 0,71 / 0,80 |
| akış | 3/14/0/7 | 1,00 / 0,18 / 0,30 | 8/9/1/6 | 0,89 / 0,47 / 0,61 |

Vaka bazında değişimler:

- **calibre-web kapak SSRF'i (CVE-2022-0939): kaçıyordu, şimdi bulunuyor.** İz `editbooks.py:778`'deki form
  girdisinden `save_cover_from_url(url)` üzerinden `helper.py:737`'deki `requests.get()`'e gidiyor. Bulgu
  düzeltilmiş sürümde kalkıyor.
- **Archery GHSL-2022-104: kaçıyordu, şimdi orta güvenle bulunuyor.** Archery 101 ve 102'de bulgular P3'ten P1'e
  çıktı.
- **Langflow `validate.py`: düşük güvenden yüksek güvene ve tam akışa çıktı.** Bulgu düzeltilmiş sürümde de
  duruyordu; şimdi izi de var, bu yüzden akış seviyesinde ilk FP'yi veriyor (akış FP 0 → 1).
- **Kaçmaya devam edenler:** pyLoad (`eval_js`) ve Ray (`profile_manager`).

### Held-out (görülmeyen), 13 vaka, mühür doğrulandı

| Seviye | D3 = D4 = D5 TP/FN/FP/TN | P / R / F1 |
|---|---|---|
| dosya | 5/8/5/8 | 0,50 / 0,39 / 0,43 |
| açık | 4/9/4/9 | 0,50 / 0,31 / 0,38 |
| tam satır | 4/9/4/9 | 0,50 / 0,31 / 0,38 |
| akış | 3/10/2/11 | 0,60 / 0,23 / 0,33 |

**Performans artışı yok.** FP de FN de değişmedi. Held-out'u açmamak için hangi vakaların neden kaçtığına
bakılmadı. Dev ile held-out arasındaki fark (tam satır recall'ü 0,71'e karşı 0,31) D4-D5'ten sonra büyüdü. Bunun
anlamı: D5'in yakaladığı türden açıklar (proje içi yardımcıdan geçen param→sink akışı) dev setinde var, held-out'taki
kaçan vakalarda ya yok ya da bu mekanizmanın ulaşmadığı bir yerde kırılıyor. Dev ve sentetik setteki kazanımın
genellendiği söylenemez.

### Sentetik çok dosyalı set (görülen), 14 puanlanan senaryo

| Seviye | D3 = D4 TP/FN/FP/TN | D3 = D4 P / R / F1 | D5 TP/FN/FP/TN | D5 P / R / F1 |
|---|---|---|---|---|
| dosya | 9/5/3/11 | 0,75 / 0,64 / 0,69 | 14/0/3/11 | 0,82 / 1,00 / 0,90 |
| açık | 9/5/3/11 | 0,75 / 0,64 / 0,69 | 14/0/3/11 | 0,82 / 1,00 / 0,90 |
| tam satır | 7/7/1/13 | 0,88 / 0,50 / 0,64 | 14/0/1/13 | 0,93 / 1,00 / 0,97 |
| akış | 3/11/1/13 | 0,75 / 0,21 / 0,33 | 13/1/1/13 | 0,93 / 0,93 / 0,93 |

D1-D3 raporundaki sentetik sayılardan farklı olmasının nedeni D4 öncesi yapılan işaret düzeltmesi (sarmalayıcının
çağrıldığı satır da sink sayılıyor). D3 de bu yeni işaretlerle yeniden ölçüldü.

- **Kalan tam satır FP'si:** s13, tipli FastAPI parametresi (`item_id: int`). Bu D6'nın konusu. D5'ten önce bu
  senaryo hiç bulgu vermiyordu; şimdi açık ve güvenli ikizin ikisi de bulgu veriyor.
- **s12 (getattr):** kesinlik iddia eden bulgu yok, beklendiği gibi.

**Uyarı:** D5 geliştirilirken bu set kullanıldı (s07, s09 ve s11 güvenli ikizleri yanlış bayraklanıyordu ve
düzeltildi). Yapılan düzeltmeler genel kurallar, ama bu setteki sonuç iyimser okunmalı.

### Bulgu sayısı ve öncelik dağılımı

| Set | D3 | D4 | D5 |
|---|---|---|---|
| Dev, açık sürümler | 756 (P1: 65) | 754 (P1: 65) | 826 (P1: 147) |
| Held-out, açık sürümler | 347 (P1: 52) | 347 (P1: 52) | 447 (P1: 152) |
| Held-out, düzeltilmiş sürümler | 345 | 345 | 445 |

**Dev'deki ek bulgulara bakıldı** (held-out'takilere bakılmadı). Üç gruba ayrılıyorlar.

1. **Gerçek görünenler.** Archery `ChartDao` içinde `request.GET`'ten gelen `checksum` SQL'e biçimleniyor. Archery
   `MssqlEngine.get_all_tables(db_name)` da benzer. calibre-web'de form alanından dosya yoluna giden akışlar var.
2. **Tasarım gereği olanlar.** Archery ve pgAdmin'in sorgu aracı kullanıcının SQL'ini çalıştırmak için var.
3. **Muhtemel yanlış pozitifler.**
   - FastAPI'de `request: Request` gibi çerçeve nesneleri parametre olarak kaynak sayılıyor. Open WebUI'de
     `request.app.state.config.WEBHOOK_URL` "kullanıcı girdisi" oluyor.
   - Veritabanından okunan kayıt, bilinmeyen çağrı kuralı (K8) yüzünden kimliği taşıyan argümanın taint'ini
     alıyor. pgAdmin'de `Process.query.filter_by(pid=...)` sonucundan `shutil.rmtree()`'ye giden akış böyle.
   - Django QuerySet'in `.exists()` metodu dosya yolu metodu sanılıyor.

Bu gruplar D4-D5'in yeni hatası değil. Daha önce de olan kaynak ve K8 kuralları, artık fonksiyon sınırlarını
geçebildiği için daha çok yere ulaşıyor. Hepsi D6'nın (çerçeve modelleme, bilinmeyen çağrı politikası) konusu.

**Kalkan bulgular:**

- pgAdmin'de iki TRUSTBOUND (`auth_obj.as_dict()`, D4) ve iki XSS-RESPONSE (`return err_msg`, D5) kalktı. Her
  ikisi de yanlış pozitifti.
- pgAdmin'de sorgu aracındaki `StartRunningQuery(...).execute(sql)` SQLi bulgusu kalktı. Bu projenin kendi
  `execute` metodu, kütüphane `cursor.execute()` değil; GT'de de yok.

### Diğer ölçümler

| Ölçüm | D3 | D4 | D5 |
|---|---|---|---|
| OWASP BenchmarkPython | +0,97 | +0,97 | +0,97 |
| mini benchmark | +1,00 | +1,00 | +1,00 |
| pgAdmin süre, 3 koşu | 6,7 / 6,8 / 6,3 s | 6,6 / 6,9 / 7,1 s | 8,6 / 8,2 / 8,0 s |
| pgAdmin tepe bellek | 218 MB | 220 MB | 221 MB |
| Dev seti toplam süre | 17 s | 18-19 s | 23 s |
| Held-out toplam süre | 34 s | 35-38 s | 47 s |
| Testler | 112 geçti | 121 geçti | 132 geçti (1 atlandı) |
| RedWall'un kendi taraması | 0 bulgu | 0 bulgu | 0 bulgu |

## Yapılanlar

### D4: CallResolver (PR #5)

- Çağrı noktası ulaştığı proje tanımına bağlanıyor:
  - fonksiyon, `Class.method()`, `super().m()`;
  - tipli alıcı: `self`, factory dönüş tipi, `Class()` örneği, proje sınıfı anotasyonlu parametre;
  - MRO üzerinden kalıtılan metot.
- `self.m()` için alt sınıf override'ları da aday. Birden fazla aday ya da adla eşleşme `exact=False`.
- `getattr()` ile dinamik çağrı çözülmüyor.
- Özetler dönüş değerinin proje sınıfını (`ret_types`) taşıyor.

### D5: Summary v2

- **Parametre→sink (`param_sinks`).**
  - Fonksiyon gövdesi her parametre işaretlenerek bir kez yürünüyor. Hangi parametrenin hangi sink'e
    ulaştığı, sink'in yeri ve aradaki adımlar kaydediliyor.
  - Çağrı noktasında kullanıcı girdisi taşıyan argüman böyle bir parametreye gidiyorsa bulgu sink'in kendi
    dosyasında ve satırında raporlanıyor. İz çağıran dosyadaki kaynaktan başlıyor, "passed to `f()` as `p`"
    adımıyla çağrılana geçiyor ve sink'te bitiyor.
  - Parametreyi değiştirmeden sink'e veren ince sarmalayıcıda (`def run(cmd): os.system(cmd)`) bulgu
    çağrının yapıldığı satırda veriliyor.
  - Zincirler (f → g → sink) özetle taşınıyor.
- **Güven:** kesin çözülen çağrıda yüksek, aday override'larda ve adla eşleşmede orta.
- **Parametre→dönüş (`returns_from`):** yalnızca dönüş değerine ulaşan parametrelere verilen argümanlar sonucu
  kirletiyor. `label(prefix, item)` yalnızca `prefix`'i döndürüyorsa `item`'daki girdi sonuca geçmiyor.
- **Doğrulayıcı özetleri (`validates`).** `return name in KNOWN` ya da kontrollerden sonra `return True` diyen
  proje fonksiyonları, `if not is_known(x): abort(400)` gibi kullanımda koruma sayılıyor.
- **Bağlam duyarlılığı:**
  - Kesin çözülen kendi `execute`/`query` metodu, aynı adlı kütüphane sink'i sayılmıyor; ne olduğu metodun
    özetinden geliyor.
  - Çağıranda yapılan temizleme (örneğin `shlex.quote`) çağrılandaki sink'e kadar taşınıyor.
- **abort()/sys.exit():** bu çağrılarla biten dal artık çıkış sayılıyor. Faz 1 belgesinde yazıyordu ama
  bağlanmamıştı. Hem satır içi hem yardımcı fonksiyonlu doğrulamalar için gerekliydi.
- **Özyineleme:** özet sabit noktaya kadar (en fazla 3 tur) yineleniyor. Karşılıklı özyinelemede tahmine
  dayanan ara özetler önbelleğe alınmıyor. Bir dış özetin altında en fazla 400 özet hesaplanıyor.
- **explain:** kaynak başka dosyadaysa açıklama `dosya:satır` gösteriyor.
- **Testler:** `tests/test_summary_v2.py` (11 test). Hepsi D4 kodunda kalıyor.

## Sınırlar ve D6 için notlar

- **Held-out'ta kazanım yok.** D5'in kazanımları görülen setlerde. Bir sonraki adım held-out'u açmadan, dev'deki
  yanlış pozitif gruplarını (çerçeve nesnesi kaynak sayılması, K8, QuerySet) genel kurallarla azaltmak olmalı.
- **Nesne alanları izlenmiyor.** `self.x` bir metotta atanıp başka metotta okunduğunda bağ kopuyor.
- **FastAPI tipli parametreleri (`item_id: int`) henüz temiz sayılmıyor.**
- **Sıralama ve gürültü:** P1 bulgu sayısı yaklaşık üç katına çıktı. Bu, raporu okuyan kişi için gerçek bir
  maliyet; calibre-web SSRF'i 45 bulgu içinde 26. sırada.
- **Held-out küçük:** 13 vaka. Bir vaka yaklaşık 7,7 puan ediyor.

Ham sonuçlar: `benchmarks/results/faz3/` altında `dev-d4`, `dev-d5`, `heldout-d4`, `heldout-d5`, `synthetic-d4`
ve `synthetic-d5`.
