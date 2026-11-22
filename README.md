# RedWall

RedWall, açık kaynak ve bilgisayarında yerel çalışan bir güvenlik tarayıcısıdır
(SAST: kodu çalıştırmadan okuyup güvenlik açığı arayan araç). Hedefi şu:

1. **Önce hızlı ve tekrarlanabilir kurallar tarar.** Aynı kod her seferinde aynı sonucu verir, CI'da saniyeler sürer.
2. **Sonra yapay zekâ yalnızca aday bulguları doğrular** (yol haritasında Faz 2). Yerel model ya da isteğe bağlı bulut.
3. **Hiçbir bulgu sessizce silinmez.** Yapay zekâ bir bulguya şüpheyle bakarsa önceliğini düşürür ve gerekçesini yazar.

> Durum: **Faz 0 / erken sürüm.** Kural motoru, CLI, rapor formatları ve ölçüm düzeneği hazır.
> Yapay zekâ doğrulama, dosyalar arası analiz ve kanıt testleri sonraki fazlarda.

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
redwall scan --min-confidence medium      # düşük güvenli adayları gizle
redwall rules                             # tüm kuralları listele
```

Örnek çıktı:

```
HIGH     app.py:23:5  RW-PY-SQLI  SQL injection
         SQL query passed to `cur.execute()` is user input. (confidence: high, CWE-89)
         > cur.execute(query)
           line 20: user input enters via `request.args`
           line 20: stored in `uid`
           line 21: stored in `query`
           line 23: reaches sink `cur.execute()`
```

Bir bulguyu bilerek kabul ediyorsan satırın sonuna (veya bir üst satıra) yorum ekle:

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
- **Güven seviyesi:** kullanıcı girdisi → `high`, sabit olmayan parçalarla kurulmuş metin → `medium`,
  bilinmeyen değer → `low`. Bu, Faz 2'de yapay zekânın hangi bulgulara bakacağını belirleyecek.
- **Parmak izi:** her bulgunun satır kaymalarına dayanıklı sabit bir kimliği var (`kural + dosya + fonksiyon + satır metni`).
  Reddedilen bulguları hatırlamak ve önbellek için kullanılacak.
- **Bulgu durumu:** şimdilik hepsi `candidate`. Sonraki fazlar `confirmed`, `proven` veya `deprioritized` yapacak, asla silmeyecek.

## Kurallar

| Motor | Kurallar |
|---|---|
| python-ast | SQL injection, komut enjeksiyonu, eval/exec, güvensiz deserialization (pickle, yaml.load), SSTI, Markup XSS, path traversal, SSRF, `verify=False`, `debug=True`, MD5/SHA-1, `tempfile.mktemp` |
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
  models.py         Finding / Rule / ScanResult veri modelleri
  engines/          python_ast.py, opengrep.py, secrets.py
  rules/opengrep/   JS/TS kuralları (YAML)
  reporters/        text, json, jsonl, sarif, markdown
  bench.py          OWASP formatında benchmark puanlama
tests/              birim testleri ve beklenti işaretli örnek dosyalar
benchmarks/         mini benchmark ve OWASP BenchmarkPython betiği
```

## Lisans

MIT
