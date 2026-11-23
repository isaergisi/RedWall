# RedWall

RedWall, açık kaynak ve bilgisayarında yerel çalışan bir güvenlik tarayıcısıdır
(SAST: kodu çalıştırmadan okuyup güvenlik açığı arayan araç). Hedefi şu:

1. **Önce hızlı ve tekrarlanabilir kurallar tarar.** Aynı kod her seferinde aynı sonucu verir, CI'da saniyeler sürer.
2. **Sonra bulguları risk sırasına dizer ve her birinin neden hâlâ açık olduğunu yazar.** İsteğe bağlı olarak
   yerel bir dil modeli ikinci görüş ekleyebilir.
3. **Hiçbir bulgu gizlenmez.** Yapay zekâ bir bulguyu silemez; sırasını en fazla birkaç puan oynatabilir ve gerekçesini yazar.

> Durum: **Faz 2.** Bulgular P1-P4 öncelik sırasıyla ve "neden hâlâ açık" gerekçesiyle raporlanıyor; opsiyonel
> LLM ikinci görüşü var. OWASP BenchmarkPython'da **+0,97**, ama daha önce görülmemiş 8 gerçek projede yüksek
> öncelikli bulguların kesinliği yalnızca **%5-16** ve 17 bilinen açığın 13'ü işaretleniyor. Yani benchmark skoru
> gerçek dünyaya taşınmıyor (ayrıntı: [Ölçüm](#ölçüm) ve [Faz 2 raporu](docs/arastirma/faz2-genelleme-raporu.md)).
> Dosyalar arası analiz ve kanıt testleri sonraki fazlarda.

## Kurulum

```bash
pip install -e .          # şimdilik depodan; PyPI'a Faz 1'de çıkacak
redwall --version
```

Hiçbir bağımlılığı yok, sadece Python 3.10+ gerekir. JavaScript/TypeScript kuralları için
[Opengrep](https://github.com/opengrep/opengrep) (veya Semgrep CE) PATH'te olmalıdır; yoksa RedWall
bunu raporda belirtir ve diğer taramalara devam eder.

## Kullanım

```bash
redwall scan                              # bulunduğun klasörü tara
redwall scan src/ -f sarif -o redwall.sarif   # GitHub code scanning için SARIF
redwall scan --out-dir .redwall/results   # report.md + findings.jsonl + results.sarif
redwall scan --fail-on medium             # orta ve üstü bulguda CI'ı kır (varsayılan: high)
redwall scan --min-confidence medium      # düşük güvenli adayları rapora alma (kaç tane olduğu yine yazılır)
redwall scan --lang tr                    # açıklamalar Türkçe
redwall scan --brief                      # terminalde "neden açık" açıklamalarını kısalt
redwall scan --llm ollama:qwen2.5-coder:7b   # opsiyonel yerel LLM ikinci görüşü
redwall rules                             # tüm kuralları listele
```

Örnek çıktı (`--lang tr`). Bulgular en kritik olandan başlayarak sıralanır; `#1` sırayı, `P1` kademeyi,
`87` puanı gösterir:

```
#1   P1  87  HIGH     app.py:23:5  RW-PY-SQLI  SQL injection
         SQL query passed to `cur.execute()` is user input. (confidence: high, CWE-89)
         > cur.execute(query)
           line 20: user input enters via `request.args`
           line 20: stored in `uid`
           line 21: stored in `query`
           line 23: reaches sink `cur.execute()`
         Neden hâlâ açık:
           - Kullanıcı girdisi 20. satırda `request.args` ile giriyor ve 23. satırda `cur.execute()` çağrısına ulaşıyor (izde 4 adım).
           - RedWall şunları arar: parametreli sorgu (sabit SQL metni, değerler ayrı verilir), int()/UUID dönüşümü veya `if x not in IZINLI: return` gibi bir izin listesi kontrolü. Bu yolda hiçbiri yok.
           - Değer bu fonksiyonun dışında doğrulanıyorsa (dekoratör, form sınıfı, ara katman) bunu gerekçesiyle `# redwall: ignore[RW-PY-SQLI]` olarak kaydedin; bulgu o zaman susturulmuş olarak listelenir.
           - Durum `candidate`: hiçbir inceleyici, LLM veya kanıt adımı onu doğrulamadı ya da reddetmedi ve satırda `redwall: ignore` işareti yok; bu yüzden hâlâ açık.
         Öncelik puanı: 87 = +42 (etki: saldırgan uygulamanın erişebildiği veriyi okuyup değiştirebilir) +30 (kanıt: kullanıcı girdisi sink'e kadar izlendi) +15 (maruziyet: veri bir HTTP isteğinden geliyor (uzaktan erişilebilir))
```

Bir bulguyu bilerek kabul ediyorsan satırın sonuna (veya bir üst satıra) yorum ekle. Susturulan bulgu
silinmez: raporda ayrı bir bölümde (SARIF'te `suppressions` ile) listelenmeye devam eder.

```python
os.system(cmd)  # redwall: ignore[RW-PY-CMDI]
```

Çıkış kodları: `0` eşik üstü bulgu yok, `1` var, `2` kullanım hatası.

## Nasıl çalışır

```
kod ──► 1. Tara (bu sürüm) ──► 2. Birleştir ──► 3. Doğrula (LLM) ──► 4. Kanıtla ──► 5. Düzelt
         ├─ python-ast  : Python AST kuralları + fonksiyon içi kirli veri izleme
         ├─ opengrep    : JS/TS kuralları (redwall/rules/opengrep)
         └─ secrets     : sabit yazılmış şifre / anahtar (değerler raporda maskelenir)
```

- **Kirli veri (taint) izleme:** `request.args`, `input()`, rota parametreleri gibi kullanıcı girdilerini
  işaretler ve tehlikeli bir çağrıya (`cursor.execute`, `os.system`, `eval` ...) ulaşıp ulaşmadığını izler.
  Ulaşırsa bulgu **yüksek güvenli** olur ve kaynaktan hedefe adım adım yol gösterilir.
- **Yanlış alarmı azaltan analizler (Faz 1):**
  - *Sabit katlama:* `if 7 * 42 - num > 200:` gibi her zaman doğru/yanlış olan koşullar hesaplanır, ölü dal yürünmez.
    `x if <sabit> else y` ve sabit değerli `match` de tek dala iner.
  - *Yol birleştirme:* `if`/`match`/`try`/döngüler kapsamın kopyası üzerinde yürünüp sonra birleştirilir; her zaman
    `return` eden bir dal sonraki koda değer sızdırmaz.
  - *Kapsayıcı takibi:* sabit anahtar/indeksli `dict`, `list`, `ConfigParser` eleman eleman izlenir
    (`m["b"] = girdi; m["a"]` okumak güvenlidir, `lst.pop(0)` sonrası indeksler kayar).
  - *Sink'e özgü sanitizer:* `html.escape` değeri yalnızca XSS için temizler, `shlex.quote` yalnızca kabuk için,
    `int()` her yer için.
  - *Doğrulama guard'ları:* `if x not in IZINLI: return`, `if "../" in x: return` (yalnızca path için) ve
    normalleştirilmiş yolda `startswith` kontrolü, kontrolün geçtiği yolda değeri temizler.
  - *Yardımcı fonksiyon özetleri:* taranan dosyalardaki fonksiyon/metotlar önce özetlenir (kullanıcı girdisi döndürür /
    argümanını geçirir / sabit döndürür). `wrapper.get_form_parameter()` kaynak, hep sabit döndüren yardımcı güvenli sayılır.
- **Güven seviyesi:** kullanıcı girdisi → `high`, sabit olmayan parçalarla kurulmuş metin → `medium`,
  bilinmeyen değer → `low`. Bu, Faz 2'de yapay zekânın hangi bulgulara bakacağını belirleyecek.
- **Parmak izi:** her bulgunun satır kaymalarına dayanıklı sabit bir kimliği var (`kural + dosya + fonksiyon + satır metni`).
  Reddedilen bulguları hatırlamak ve önbellek için kullanılacak.
- **Bulgu durumu:** açık bulgular `candidate`, satır içinde kabul edilenler `suppressed`. Sonraki fazlar `confirmed`,
  `proven` veya `deprioritized` yapacak, asla silmeyecek.

### Faz 2: önceliklendirme ve açıklama

- **Risk puanı (0-100):** etki (CWE'ye göre, kod çalıştırma en üstte) + kanıt (girdi sink'e kadar izlendi mi) +
  maruziyet (HTTP isteği mi, yerel kullanıcı mı) + bağlam (test/örnek kodu daha aşağıda). Kademeler: P1 80-100,
  P2 60-79, P3 40-59, P4 0-39. Her terimin gerekçesi raporda yazar, aynı kod hep aynı sırayı verir.
- **Neden hâlâ açık:** her bulgu için izden kanıt, RedWall'un aradığı ama bu yolda bulamadığı önlemler, varsa yanlış
  türde bir temizleyici (`html.escape` SQL'i korumaz), analizin göremediği yerler ve nasıl kapatılacağı.
- **Hiçbir şey gizlenmez:** susturulanlar ayrı bölümde, filtrelerle dışarıda kalanların sayısı raporda.
- **Opsiyonel LLM (`--llm`):** Ollama veya OpenAI uyumlu bir uç (llama.cpp, LM Studio, vLLM). Varsayılan olarak
  yalnızca `localhost`; uzak uç için `--llm-allow-remote` gerekir, sır bulguları hiç gönderilmez. Model yalnızca not
  ekler ve puanı en fazla ±8 oynatır; bunu da ancak gösterilen koddaki satırları kanıt verirse yapar. Hata olursa
  deterministik sıra kalır. Çekirdek hâlâ sıfır bağımlılık. (Gerçek bir modelle karar kalitesi henüz ölçülmedi.)

## Kurallar

| Motor | Kurallar |
|---|---|
| python-ast | SQL injection, komut enjeksiyonu (`shell=True` ve `["sh", "-c", ...]` listeleri), eval/exec, güvensiz deserialization (pickle, yaml.load), SSTI, yansıyan XSS (Flask view dönüşü, `make_response`, Django `HttpResponse`) ve Markup XSS, path traversal (`open`, `codecs.open`, `os.path.*`, `pathlib`), SSRF, LDAP injection, XPath injection, XXE (dış varlıkları açık sax/lxml parser), açık yönlendirme, güven sınırı ihlali (oturuma kullanıcı girdisi), zayıf rastgele sayı (`random.*`), `secure` bayraksız cookie, `verify=False`, `debug=True`, MD5/SHA-1, `tempfile.mktemp` |
| opengrep (JS/TS) | eval / new Function, child_process komut enjeksiyonu, SQL injection, innerHTML / document.write / dangerouslySetInnerHTML XSS, `rejectUnauthorized: false`, MD5/SHA-1 |
| secrets | Özel anahtar, AWS, GitHub, Slack, Stripe, Google API anahtarı, entropiye göre genel şifre/token |

Kuralların tamamı RedWall için sıfırdan yazıldı (MIT). Semgrep'in kendi kural paketi lisansı rakip ürünlerde
kullanıma izin vermediği için kullanılmıyor.

## Ölçüm

İddialarımızı sayıyla göstermek için her değişiklik ölçülür. Ayrıntılar: [benchmarks/README.md](benchmarks/README.md).

```bash
redwall bench benchmarks/mini/testcode --expected benchmarks/mini/expectedresults-mini.csv
benchmarks/owasp_python.sh                # OWASP BenchmarkPython (internet gerekir)
```

| Sürüm | OWASP BenchmarkPython v0.1 (1230 test) | Ortalama TPR | Ortalama FPR | Skor (TPR − FPR) |
|---|---|---|---|---|
| Faz 0 | 6 kategoride kural | %30 | %15 | +0,15 |
| Faz 1 | 14 kategorinin hepsinde kural | %100 | %3 | **+0,97** |
| Faz 2 | Faz 1 + gerçek kodda bulunan 4 genelleme hatasının düzeltmesi | %100 | %3 | **+0,97** |

**Görülmemiş gerçek projeler (Faz 2).** Benchmark'a bakılarak yazılan kuralların genellenip genellenmediğini görmek
için Faz 0/1'de hiç bakılmamış 8 projede, yayımlanmış açıkların bulunduğu sürümler tarandı
([`benchmarks/realworld/`](benchmarks/realworld/), `python benchmarks/realworld/run.py --bandit`):

| | Faz 0 | Faz 1 | Faz 2 | Bandit |
|---|---|---|---|---|
| 17 bilinen açıktan işaretlenen | 13 | 12 | 13 | 10 |
| ... açığa özgü satırda | 9 | 8 | 9 | 10 |
| P1/P2 bulgularda kesinlik (elle etiketli örneklem) | | %5 (40 bulgu) | %16 (25 bulgu) | |

Faz 1'in benchmark kalıbından genellenmiş bir kuralı (`startswith` kontrolünü temizleyici saymak) Gerapy'deki gerçek
bir komut enjeksiyonunu kaybettiriyordu. Kural düzeltilince açık geri geldi ve OWASP skoru hiç değişmedi: benchmark bu
farkı göremiyor. Bilinen açıkların yakalanamayanları çoğunlukla dosyalar arası akıştan ve tanınmayan kaynak/sink'lerden
(aiohttp, `http.server`, `js2py`) kaynaklanıyor. Tüm tablo, yöntem, etiketler ve sınırlar:
[Faz 2 genelleme raporu](docs/arastirma/faz2-genelleme-raporu.md).

Dürüst not: Faz 1 kuralları benchmark'ın test kalıpları incelenerek tasarlandı, yani bu skor "görülmüş veri"
üzerinde. Bunu dengelemek için her teknik genel tutuldu (benchmark'a özel isim, dosya ya da sabit yok) ve
gerçek projelerde (pygoat, Vulnerable-Flask-App, dvpwa, flask, requests, django) Faz 0'ın bulduğu hiçbir bulgunun
kaybolmadığı kontrol edildi. Kalan 5 yanlış alarm `request.path.split("/")[1]` kaynağından geliyor: bu değer
benchmark'ta hep sabit `benchmark` kelimesi, RedWall ise onu bilinmeyen sayıyor ve bilerek böyle bırakıldı.

## Geliştirme

```bash
pip install -e '.[dev]'
pytest
```

Proje yapısı:

```
redwall/
  cli.py            komut satırı
  scanner.py        dosya bulma, motorları çalıştırma, tekilleştirme, susturma, parmak izi
  triage/           risk puanı ve sıralama, "neden açık" açıklamaları, opsiyonel LLM katmanı
  models.py         Finding / Rule / ScanResult veri modelleri
  engines/          python_ast.py, opengrep.py, secrets.py
  rules/opengrep/   JS/TS kuralları (YAML)
  reporters/        text, json, jsonl, sarif, markdown
  bench.py          OWASP formatında benchmark puanlama
tests/              birim testleri ve beklenti işaretli örnek dosyalar
benchmarks/         mini benchmark, OWASP BenchmarkPython betiği, görülmemiş gerçek projeler (realworld/)
```

## Lisans

MIT
