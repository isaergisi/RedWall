# Faz 3, D1-D3: ölçüm altyapısı, hata yalıtımı ve import çözümleme

## Kısa sonuç

- **Tespit değişmedi; bu beklenen sonuç.** Dev setinde 13/17, held-out'ta 4/13, sentetik sette 8/14.
  Akış doğrulamalı seviyede sırasıyla 3/17, 3/13 ve 3/14. D3 import'ları çözüyor, ama özetler hâlâ yalnızca
  dönüş değerini taşıyor (K2). Parametreden sink'e giden akışlar D4 (CallResolver, Summary v2) gelmeden
  görünmez.
- **Import çözümleme:** projenin kendi import'larının çözülme oranı dev setinde yaklaşık %7'den %99,3'e,
  held-out'ta %2,2'den %97,2'ye çıktı. Daha önce 13 held-out projesinin 8'inde, dev projelerinin 5'inde
  oran sıfırdı.
- **Hata yalıtımı:** bir fonksiyondaki analizör hatası artık yalnızca o fonksiyonun kalanını atlıyor.
  Önceden tek bir hata python-ast'in bütün bulgularını siliyordu. Hata `errors` listesine dosya, satır ve
  fonksiyon adıyla yazılıyor.
- **Held-out ile dev arasındaki fark büyük.** Açık seviyesinde recall dev'de 0,77, held-out'ta 0,31. Faz 2
  kurallarının bir kısmı görülen projelere göre şekillenmiş; Faz 3'ün asıl hedefi bu fark.
- **Bulgu sayısı biraz değişti** (dev 753 → 756, held-out 353 → 347). Ayrıntı ve açık soru aşağıda.

## Seviyeler ve setler

| Seviye | Bulgu ... |
|---|---|
| dosya | doğru CWE ile bir GT sink dosyasında (herhangi bir satır) |
| açık | GT sink satırında veya aralığında (genel `shared` yardımcılar dahil; Faz 2'deki "tespit") |
| tam satır | danışmaya özgü (shared olmayan) sink satırında |
| akış | tam satırda ve izi GT kaynak satırından (doğru dosyada) başlıyor |

TP ve FN açık sürümlerden geliyor. FP ve TN, düzeltilmiş sürüme satır eşlemesiyle taşınan aynı kontrolden
geliyor. Bu yüzden precision, düzeltilmiş sürüme karşı vaka düzeyinde precision'dır; projedeki bütün
bulguların precision'ı değildir.

| Set | Görüldü mü? | Vaka |
|---|---|---|
| `benchmarks/realworld/cves.json` | görüldü (Faz 2'den beri dev seti) | 17 vaka, 8 proje |
| `benchmarks/heldout/cases.json` | görülmedi; motor değişikliğinden önce mühürlendi | 13 vaka, 13 proje |
| `benchmarks/synthetic/` | görüldü (Faz 3 için yazıldı) | 15 senaryo, açık ve güvenli ikiz |

## Önce ve sonra

"Önce" main dalı (`8b17a8c`), "sonra" bu dalın son hali. İki ağaç aynı koşuda ölçüldü.

### Dev seti (görülen), 17 vaka

| Seviye | Önce TP/FN/FP/TN | Önce P / R / F1 | Sonra TP/FN/FP/TN | Sonra P / R / F1 |
|---|---|---|---|---|
| dosya | 14/3/1/6 | 0,93 / 0,82 / 0,88 | 14/3/1/6 | 0,93 / 0,82 / 0,88 |
| açık | 13/4/1/6 | 0,93 / 0,77 / 0,84 | 13/4/1/6 | 0,93 / 0,77 / 0,84 |
| tam satır | 9/8/1/6 | 0,90 / 0,53 / 0,67 | 9/8/1/6 | 0,90 / 0,53 / 0,67 |
| akış | 3/14/0/7 | 1,00 / 0,18 / 0,30 | 3/14/0/7 | 1,00 / 0,18 / 0,30 |

### Held-out (görülmeyen), 13 vaka, mühür doğrulandı

| Seviye | Önce TP/FN/FP/TN | Önce P / R / F1 | Sonra TP/FN/FP/TN | Sonra P / R / F1 |
|---|---|---|---|---|
| dosya | 5/8/5/8 | 0,50 / 0,39 / 0,43 | 5/8/5/8 | 0,50 / 0,39 / 0,43 |
| açık | 4/9/4/9 | 0,50 / 0,31 / 0,38 | 4/9/4/9 | 0,50 / 0,31 / 0,38 |
| tam satır | 4/9/4/9 | 0,50 / 0,31 / 0,38 | 4/9/4/9 | 0,50 / 0,31 / 0,38 |
| akış | 3/10/2/11 | 0,60 / 0,23 / 0,33 | 3/10/2/11 | 0,60 / 0,23 / 0,33 |

13 vakada tek vaka 7,7 puan ediyor; bir iki vakalık farklar gürültüdür. Vaka bazında satırlara bakılmadı.

### Sentetik çok dosyalı set (görülen), 14 puanlanan senaryo

| Seviye | Önce ve sonra TP/FN/FP/TN | P / R / F1 |
|---|---|---|
| dosya | 9/5/3/11 | 0,75 / 0,64 / 0,69 |
| açık | 8/6/3/11 | 0,73 / 0,57 / 0,64 |
| tam satır | 6/8/1/13 | 0,86 / 0,43 / 0,57 |
| akış | 3/11/1/13 | 0,75 / 0,21 / 0,33 |

Kaçanlar tam olarak D4'ün hedefi: üç dosyalı zincir, göreli import'lu zincir, factory, kalıtım, recursion
ve tipli FastAPI parametresi. `getattr` senaryosu (s12) puanlamaya girmiyor: orada sink'te kesinlik iddia
eden bulgu yok, beklenen davranış da bu.

### Diğer ölçümler

| Ölçüm | Önce | Sonra |
|---|---|---|
| OWASP BenchmarkPython | +0,97 | +0,97 |
| mini benchmark | +1,00 | +1,00 |
| pgAdmin (163K satır) süre, 3 koşu | 6,0 / 6,1 / 6,3 s | 7,1 / 7,3 / 6,8 s |
| pgAdmin tepe bellek | 215 MB | 218 MB |
| Testler | 84 (83 geçti, 1 atlandı) | 113 (112 geçti, 1 atlandı) |

Yaklaşık %15'lik süre artışı import indeksinden ve artık çözülen çağrılar için hesaplanan özetlerden
geliyor.

### Import çözümleme (dev seti, proje başına)

| Proje | Proje içi import | Önce çözülen (yaklaşık) | Sonra çözülen | Göreli import | Import döngüsü |
|---|---|---|---|---|---|
| Gerapy | 53 | 0 | 50 | 13 | 0 |
| pgAdmin | 3106 | 0 | 3106 | 600 | 4 (en büyüğü 87 modül) |
| pyLoad | 888 | 0 | 888 | 687 | 0 |
| calibre-web | 237 | 0 | 237 | 212 | 1 |
| Open WebUI | 239 | 228 | 239 | 0 | 0 |
| Langflow | 2430 | 17 | 2381 | 302 | 4 (en büyüğü 114) |
| Ray dashboard | 209 | 0 | 209 | 0 | 0 |
| Archery | 367 | 287 | 367 | 63 | 3 |

Held-out toplamı: 17.078 import'un 369'u önce (yüzde 2,2), 16.608'i sonra (yüzde 97,2) çözülüyor. 13
projenin 11'inde import döngüsü var. "Önce" sütunu eski adlandırmayla ve önek eşleşmesine izin vererek
hesaplandı, yani üst sınırdır.

## Bulgu sayısındaki değişim

Çözülen import'lar daha önce bilinmeyen çağrılara özet bağlıyor. Bu, varsayılan "argümandaki taint sonuca
geçer" davranışını (K8) değiştiriyor ve iki yönde etki ediyor.

**Dev setinde (incelendi):**

- **pgAdmin, 2 bulgu kalktı.** `validate_debug()` ve benzeri bir yardımcı çözüldü; döndürdükleri şey kullanıcı
  girdisi değil, yanıt nesnesi. Bunlar yanlış pozitifti.
- **pgAdmin, düzeltilen bir hata.** İlk ölçümde 4 yüksek güvenli yol bulgusu da kaybolmuştu. Neden yanlıştı:
  `filename_with_file_manager_path()` `return short_filepath()` ile, parametreyi kapanıştan okuyan bir iç
  fonksiyon döndürüyor, bu yüzden özet onu "temiz" sandı. Bu durum artık özet almıyor (varsayılan davranış).
  Test eklendi ve 4 bulgu geri geldi.
- **pyLoad, 3 bulgu geldi.** `get_redirect_url()` çözülünce `next` parametresi kaynak olarak görünür oldu (2 açık
  yönlendirme). Yardımcıdaki `is_safe_url` kontrolü henüz doğrulayıcı olarak tanınmıyor; bu D4'teki
  `validates` özetinin işi. Üçüncüsü, kendi `render_template()` sarmalayıcısının sonucunun XSS diye
  raporlanması; bu muhtemelen yanlış pozitif ve K8 kaynaklı.
- **calibre-web, 2 bulgu geldi.** `edit_book_read_status()` sonucu XSS diye raporlanıyor. Bu da K8 kaynaklı ve
  muhtemelen yanlış pozitif.

**Held-out'ta (incelenmedi):** iki projede 6 yüksek güvenli bulgu kalktı (5 yol, 1 XSS), yeni bulgu yok. GT
vakalarının hiçbiri etkilenmedi. Held-out'u açmamak için nedenine bakılmadı. Dev'de aynı türden bir değişimin
yanlış gerekçeli olduğu ortaya çıktı ve düzeltildi. Bunların da aynı türden olup olmadığı açık bir soru.

## Yapılanlar

**D1:**

- 4 seviyeli puanlama ve düzeltilmiş sürümle FP/TN (`benchmarks/realworld/score.py`).
- `run.py` artık `--manifest` alıyor, mühürü kontrol ediyor ve mühürlü sette yalnızca toplamı yazıyor.
- Dev vakalarına kaynak satırları eklendi.
- 15 senaryolu sentetik set; GT koddaki `# gt:` işaretlerinden okunuyor.
- Seçim protokolüyle mühürlü held-out seti ve değişiklik öncesi ölçüm (`benchmarks/results/faz3/`).

**D2:**

- Fonksiyon, deyim, özet ve dosya düzeyinde hata yalıtımı.
- Ayrıştırmada SyntaxWarning bastırılıyor.
- `TraceStep` alanlarına isteğe bağlı `path`, `function` ve `kind` eklendi; JSON geriye uyumlu.
- SARIF codeFlows her adımı kendi dosyasıyla veriyor; metin ve markdown raporları başka dosyadaki adımı
  `dosya:satır` olarak gösteriyor.

**D3 (`redwall/analysis/index.py`):**

- Modül adı `__init__.py` zincirinden bulunuyor; src/ düzeni ve alt dizini taranan paketler de destekleniyor.
- Göreli import'lar ve paket re-export'ları çözülüyor.
- Monorepo ve sembolik bağlantı düzeni için dış paket öneki tanınıyor.
- Import grafı ve özyinelemesiz Tarjan ile import döngüleri.
- Motor ayrıntısında "project imports resolved: X/Y, N import cycles" satırı.

## Sınırlar

- Akış seviyesi şu an yalnızca aynı dosyada başlayan izleri görebilir, çünkü motor henüz dosya aşan iz
  üretmiyor. D2 bunun altyapısını hazırladı.
- Held-out 13 vaka; yüzdeler kaba.
- Sentetik seti RedWall geliştiricileri yazdı. Bu set bir genelleme ölçüsü değil, regresyon ölçüsüdür.
