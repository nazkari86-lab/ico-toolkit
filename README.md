# ICO/CTF toolkit for Apple Silicon

Репозиторий можно разместить в любом каталоге. Набор рассчитан на локальный
анализ файлов, дампов и задач, которые явно разрешены условием.

## Запуск

```sh
source ./env.sh
```

После этого доступны локальные `stegseek` и `steghide`, Ruby-утилита `zsteg`, а
также Python-инструменты из выбранного окружения.
Для классификации числовых видеосубтитров установите один раз необязательные
офлайн-зависимости в активированное окружение:

```sh
python3 -m pip install -r $ICO_TOOLKIT_ROOT/requirements-optional-ml.txt
```

Без них остальные профили работают, а subtitle-решатель сообщает точную
причину пропуска вместо того, чтобы молча считать задачу проверенной.
Для расшифровки Windows Group Policy Preferences `cpassword` установите AES-backend:

```sh
python3 -m pip install -r $ICO_TOOLKIT_ROOT/requirements-optional-forensics.txt
```

Без AES-backend такие XML-файлы остаются в `needs-review` с причиной пропуска.
Этот же набор включает PyCryptodome, даёт статический разбор VBA и чтение
локальных SAM/SYSTEM для нескольких профилей DownUnderCTF 2024; макросы и
бинарники задач при этом не запускаются.

Для нескольких задач DownUnderCTF 2024 есть отдельные офлайн-профили.
`My Array Generator` восстанавливает ключ из соседних `plaintext`/`ciphertext`
и статически прочитанного Python-кода, затем проверяет преобразование на всём
ciphertext. Исходный скрипт не запускается; нужен `z3` CLI (на macOS:
`brew install z3`). `Ternary Brained` декодирует base-3 Brainfuck во встроенном
интерпретаторе с лимитами; ELF `encoder` не запускается. `Three Line`
анализирует повторяющийся XOR-поток, `Macro Magic` связывает VBA и HTTP-захват,
а `SAM I AM` читает только локальные SAM/SYSTEM hive-файлы и проверяет хэш по
ограниченным локальным словарям. Эти значения остаются `candidate` до проверки
исходным checker-ом или платформой. `Number Mashing` статически проверяет
конкретную AArch64-цепочку signed division и пишет файл ввода со статусом
`payload-ready`; сам бинарник и сервис не запускаются, а флаг из отсутствующего
`flag.txt` не выдумывается. `Dungeon` разбирает карту комнат и callback-
переключатели, затем пишет кратчайший статически проигранный ввод. `Vector
Overflow` проверяет соседство глобального буфера и метаданных `std::vector` в
non-PIE ELF и создаёт бинарный stdin, который по исходнику ведёт к shell. Это
`payload-ready`, а не полученный флаг: приложенного `flag.txt` нет, а бинарник и
сервис не запускаются.

`Average Assembly Assignment` генерирует программу и проверяет, что все
переходы ведут на объявленные метки; `sign in` формирует статический сценарий
сессии по проверенной паре исходника и ELF. Оба профиля дают `payload-ready`,
но требуют внешнего checker-а или разрешённой сессии для получения флага.

Для статического разбора x86-64 ELF, targeted AArch64-профиля и анализа
успешной ветки установите Capstone:

```sh
python3 -m pip install -r $ICO_TOOLKIT_ROOT/requirements-optional-reverse.txt
```

Эта группа также ставит PyCryptodome для локальной AES-GCM-расшифровки
`Rusty Vault` и восстановления ключа `Adorable Encrypted Animal`.

CyberChef можно открыть так:

```sh
open $ICO_TOOLKIT_ROOT/CyberChef/app/CyberChef_v11.5.0.html
```

## Автономный локальный анализ

Для финального формата есть отдельная copy-ready команда `ico-solve`. Она
группирует файлы по истории и категории, запускает task-aware решатели,
универсальное ядро и расширенный локальный набор адаптеров, а в stdout выводит
только выбранный флаг:

```sh
source ./env.sh
ico-solve path/to/task-or-archive
ico-solve path/to/story --mode full --debug ./ico-solve-debug
ico-solve --tools
```

Профильный запуск выполняется стадиями с bounded-параллельностью: дешёвые
проверки идут первыми, затем специализированные и тяжёлые. Число воркеров,
общий дедлайн и постоянный кэш можно задать явно:

```sh
ico-solve path/to/story --workers 6 --deadline 180 --cache ./ico-solve-cache --debug ./ico-solve-debug
```

Ключ кэша включает SHA-256 входа, контекст задачи, исполняемый файл и
аргументы; изменение файла или условия автоматически создаёт новый результат.
Производные текстовые файлы из carving и декомпиляции один раз возвращаются в
универсальный registry. Для измерения времени и покрытия есть локальный
benchmark:

```sh
python3 scripts/benchmark_ico_solve.py path/to/task --mode fast --repeat 2
```

Встроены локальные адаптеры CyberChef (Base64, Base32, hex, URL, ROT13,
reverse, gzip/zlib), `binwalk`, `zsteg`, `pngcheck`, `exiftool`, `7zz`,
`steghide`, `foremost`, `tshark`, Volatility, `radare2`, GDB, `ffmpeg`,
`ffprobe`, `qpdf`, `pdftotext`, Tesseract, YARA, `jq` и `strings`. Полный
инвентарь доступен через `ico-solve --tools`; в текущем окружении он включает
также локально доступные `pwntools`, `z3`, Ghidra/Cutter, `RsaCtfTool` и
сетевые/wordlist-инструменты.

Расширенный слой теперь также учитывает `checksec`, ROPgadget/ropper,
`objdump`/`nm`/`otool`/LLDB, UPX, angr/Unicorn, `fls`/`mmls`, oletools,
GIF/audio triage, Apktool/JADX и локальные `semgrep`/TruffleHog/Gitleaks.
Профили APK декомпилируют только в bounded debug-каталог, а бинарники не
запускаются. Полный рейтинг новых и ещё не установленных специализированных
проектов находится в [TOOL_CATALOG.md](TOOL_CATALOG.md).

Дополнительный runtime подключается тем же `env.sh` и содержит
`stegoveritas`, `xortool`, `hashid`, `hashpumpy`, `bulk_extractor`, а также
`pdfid` и `pdf-parser`. `ico-solve` использует stego/PDF/disk-профили только
для соответствующих типов файлов и сохраняет их вывод в debug-каталоге.

Дополнительные статические профили выбираются по содержимому: `hashid` для
hash-like строк, `Ciphey` для ограниченных encoded/classical-cipher текстов,
`xortool` для явно похожих XOR-артефактов, `RsaCtfTool` только для RSA-
материалов, `bulk_extractor` для disk images, `one_gadget` для локальных libc
и LIEF для структурного чтения ELF/PE/Mach-O. Qiling, Unicorn, Frida,
Objection, трассировщики, password crackers и сетевые сканеры остаются
ручными/local-replica путями.

Через тот же `env.sh` доступны совместимые обёртки `Ciphey`, `peepdf`,
`hashpumpy`, `one_gadget`, `seccomp-tools`, `clairvoyance`, `graphql-cop`,
`graphw00f`, `jwt_tool`, `kiterunner` (`kr`), Qiling, Scalpel, `strace` и
`ltrace`. Qiling проверяется через `qiling --probe` в отдельном Python-runtime,
а Scalpel собирается arm64-скриптом `scripts/build_scalpel.sh` против Homebrew
TRE (`brew install keystone tre && scripts/build_scalpel.sh`). На macOS `strace` и `ltrace` показывают явный `dtruss-compat` backend:
это syscall-level диагностика, а не точная замена Linux `ltrace`; совместимый
запуск требует `ICO_ALLOW_COMPAT_TRACE=1`. Qiling и трассировщики остаются
ручными, а `scalpel-carve` добавлен в bounded офлайн-профиль. Точные источники,
pinned commit и платформенные ограничения перечислены в
[TOOL_CATALOG.md](TOOL_CATALOG.md).

`ico-solve` по умолчанию запускает только файловые офлайн-адаптеры. `nmap`,
`ffuf`, `feroxbuster`, `gobuster`, `sqlmap`, Hydra, mitmproxy, John и Hashcat
отмечаются как `local-only` и не обращаются к удалённым хостам автоматически;
их можно применять только в явно подготовленной локальной реплике и в рамках
условия задачи. Платформа ICO и её порты никогда не сканируются.

Для одного слота stdout содержит одну строку с флагом. Для истории или набора
слотов формат строки — `story/category<TAB>flag`. `--debug` сохраняет JSON с
выбранными кандидатами, запущенными адаптерами и причинами пропуска.

`ico-scan` принимает один или несколько файлов и каталогов. Он сам определяет тип, запускает профильные офлайн-анализаторы, ограниченно распаковывает архивы, повторно ставит найденные дочерние файлы в очередь и сохраняет доказательства:

```sh
source ./env.sh
ico-scan image.png
ico-scan task.bin attachments/ --out ./ico-scan-report
ico-scan $ICO_CTF_REAL_ROOT
```

`--mode full` (по умолчанию) запускает весь совместимый bounded-набор. Для
быстрого первого прохода есть `--mode fast`: он оставляет task-aware решатели,
встроенные декодеры и дешёвые профили, а дорогие OCR/binwalk/radare2/tshark
профили помечает как пропущенные. `--progress` показывает завершённые стадии в
stderr, не смешивая их с copy-friendly выводом флагов.

Для распознанного старого ICO-quals набора `--mode fast` дополнительно работает
в режиме task-first: десять специализированных решателей обрабатывают задачи,
а повторный generic-проход по PNG/WAV/PCAP sidecar-файлам отключается. Это
сохраняет локальные кандидаты и payload-ready материалы, но не создаёт тысячи
производных файлов без новой информации. Walkthrough, manual, writeup и
historical-solution документы также исключаются из slot discovery и адаптеров,
поэтому ответы из старых разборов не становятся свежими кандидатами.

В проекте есть отдельный набор синтетических регрессионных задач для ранее
неполных сценариев. Он не требует сети и не запускает бинарники:

```sh
ico-scan benchmarks/ico_synthetic_unresolved \
  --out ./ico-scan-runs/synthetic-unresolved
```

Набор проверяет естественную формулировку Caesar, Base32-фрагменты в DNS-labels
и статический ret2win/format-string разбор. `payload-ready` для ret2win требует
байтовый payload из offset и адреса, подтверждённых условием или соседним
исходником и статическим символом ELF. Для ограниченного `sprintf`-переполнения
решатель также может построить ввод только когда исходник доказывает смещение
guard-поля, sentinel и лимит `fgets`. Одни опасные импорты или диагностический
format-string probe остаются `candidate-review`; бинарники не запускаются.

Можно указывать и сам ZIP-набор. Если внутри есть `task.txt`, scanner
безопасно материализует его в `report/sources/task-packs/`, подберёт решатели и
не будет отдельно разбирать README или соседние каталоги:

```sh
ico-scan "${ICO_CTF_REAL_ROOT}_pack.zip"
```

Одиночный файл из task-каталога автоматически использует только ближайший
каталог с `task.txt`; переданный файл больше не расширяет область поиска на весь
родительский `Downloads`.

В отчёте будут `report.json`, `report.txt`, журналы вызовов в `commands/` и извлечённые материалы в `artifacts/`. Все распознанные строки сохраняются в JSON, но список `CANDIDATE VALUES` в консоли исключает `likely-placeholder` и `likely-noise`; они перечисляются отдельно как низкоприоритетные строки. Ни одна локальная строка не подтверждена платформой, и инструмент ничего не отправляет. Для real-quals консоль также отделяет низкоприоритетные строки от кандидатов.

Все flag-shaped строки остаются в JSON. Явные шаблоны вроде
`ICO{...}`, `ICO{REDACTED_1}`, `ICO{example_flag}` и `ICO{fake_flag}`, а также
совпадения с непечатаемыми символами и однобуквенным телом дополнительно
получают поле `triage` со значением `likely-placeholder` или `likely-noise` и
объяснением `triage_reason`.
Они показываются в отдельном блоке низкого приоритета, но не удаляются: даже
необычное значение нужно проверить по контексту файла. Обычная строка вроде
`ICO{network_flag}` и локальный sanity-check сохраняются как `candidate`.
В конце CLI также печатает `ACTIONABLE RESULTS` для payload-ready, review- и
session-required результатов с путями к созданным материалам. Статусы
`unsupported` от универсальных анализаторов остаются в JSON, чтобы не засорять
консоль сообщениями о каждом неприменимом профиле.

`report.json` имеет `schema_version: 2`. Вызовы внешних анализаторов
сохраняются также в `cache/` внутри текущего report directory. Ключ включает
SHA-256 входа, имя анализатора, локальную идентичность исполняемого файла,
нормализованные аргументы и хэш task-контекста; изменение bytes, `task.txt` или
соседнего evidence-файла создаёт новый результат. Повторный вызов получает
`cache-hit` с ссылкой на исходную запись, а исходные challenge-каталоги не
изменяются.

Для generic `data`, `binary` и `text`-файлов автоматически выполняется ограниченный single-byte XOR crib-анализ: ключи `0..255` проверяются на распространённые форматы (`CTF{`, `ICO{`/`ico{`, `FLAG{`/`flag{`, `HTB{`, `SECCON{`). Префиксы `DUCTF{` и `picoCTF{` распознаются по `CTF{` с сохранением левого контекста, поэтому `CTF{` внутри полного префикса не выдаётся как отдельный флаг. Для иных форматов можно добавить regex через `--flag-regex`. Для каждого совпадения в отчёте сохраняются ключ, offset и журнал `xor-single-byte`. Это не перебор значения флага и не подбор пароля; метод применяется только к локальным артефактам, когда такой XOR предусмотрен условием задачи.

Crypto-профиль также восстанавливает фиксированную перестановку символов,
когда условие указывает на shuffle/permutation, файл содержит две или больше
однозначно разрешающих перестановку известных пар и отдельную censored-пару,
а формат флага явно указан в условии. Кандидат появляется только после проверки
прямого преобразования известных и целевой пар.

Перед профильными инструментами выполняется ещё один bounded-проход по
вложенным текстовым представлениям: валидные Base64, Base32, hex и percent-URL
токены декодируются до 4 MiB, а производный файл сохраняется только если в нём
найдена flag-shaped строка. Никаких ключей, паролей или вариантов самого флага
этот проход не перебирает.

Если указать корень набора, содержащего дочерние каталоги с `task.txt`, включается task-aware режим. Он автоматически выбирает локальный решатель для каждой задачи:

| Тип условия | Решатель |
| --- | --- |
| Single-byte XOR | crib `CTF{`, ключ и offset |
| Magic bytes | gzip → Base64 |
| PNG LSB RGB | восстановление scanline-фильтров и RGB LSB |
| PCAP / PCAPNG HTTP | TCP reassembly → Bearer → Base64 |
| SQLite | `cache_entries` по `seq` → hex |
| ELF reverse | статический Capstone XOR-анализ без запуска |
| Archive layers | ZIP → XZ → TAR → single-byte XOR |
| Repair header | восстановление `PK\\x03\\x04` → ZIP → Base64 |
| WAV LSB | 16-bit PCM LSB, MSB-first |
| PNG zTXt | zlib metadata → Base64 |

Для набора `ico_ctf_real` отчёт содержит `task_results`, пошаговые derived artifacts и поля `summary.solved_tasks`, `summary.task_artifact_count` и `summary.derived_artifact_count`. Последнее считает уникальные пути выходных файлов task-, real-quals- и universal-решателей; повторные ссылки на один файл учитываются один раз. В текстовом отчёте generic и derived artifacts считаются отдельно. Если рядом найден `flag_hashes.json`, точное совпадение SHA-256 помечается как `hash-verified`; без контрольной суммы остаётся `candidate`. Универсальный fallback продолжает работать для неизвестных файлов.

Универсальная сводка считает `universal_solved_count` только для результатов со статусом `hash-verified`; статусы `candidate` идут отдельно в `universal_candidate_result_count`. CLI называет найденные строки `CANDIDATE VALUES`, поскольку локальная находка сама по себе ещё не подтверждает флаг платформой.

Для исторического набора отборочного этапа используется отдельный real-quals
режим. Корень определяется по маркерам `rev_zero.zip`, `wolf_protocol.zip`,
`five_shards.zip`, `can_you_hear.zip`, `aezakmi` и `journal`, поэтому отдельный
`task.txt` не нужен:

```sh
ico-scan $ICO_QUALS_ROOT
```

Чтобы вывести значения из сохранённого исторического walkthrough прямо в
терминал с явной пометкой источника, добавьте `--show-references`.

После task-aware решателей bounded generic pass также просматривает challenge-
артефакты набора (архивы, бинарники, изображения, PCAP и текст) обычными
offline-профилями. Walkthrough и учебные Markdown-файлы из этого прохода
исключаются, чтобы напечатанные исторические ответы не стали текущими
кандидатами. Общий single-byte XOR pass ограничен файлами до 2 MiB и
пропускается для больших бинарников, если условие явно не просит XOR; это
ограничение действует и в generic-решателе, и в основном сканере. Для большого
Nuitka-бинарника generic XOR/radare2 и для
промежуточных spectrogram PNG дорогие профили пропускаются с записью причины;
специализированные решатели этих задач всё равно сохраняют своё доказательство.

В `task_results` и `quals_task_results` появятся все десять задач. Локально
подтверждаемые преобразования выполняются без сети:

| Задача | Офлайн действие | Статус при успехе |
| --- | --- | --- |
| Rev Zero | извлечение Base64-константы из HTML, decode и reverse | `candidate` |
| Can you hear the flag? | PNG trailer → WAV → полная и фокусированная спектрограммы 2–5 кГц → ограниченный OCR | `candidate` или `candidate-review` |
| Five Shards | PCAP/PCAPNG DNS labels → Base32 → общий XOR-поток из `corrupted.wav` | `candidate` |
| Wolf Protocol | SHA-256-проверка локального ELF, инверсия 35-байтового target и точная forward-проверка | `candidate` |
| AEZAKMI | SHA-256-проверка ELF → little-endian ROP payload | `payload-ready` или `candidate-review` |
| Journal Operator | SHA-256-проверка ELF → `%n` format-string payload | `payload-ready` или `candidate-review` |
| NorthStar, Backdoor | офлайн playbook и transcript parser | `requires-authorized-session` или `transcript-derived` |
| PixelMart | transcript → LCG recovery → predicted rounds | `requires-authorized-session` или `payload-ready` |
| VIP Club | transcript → SHA-256 length-extension payload | `requires-authorized-session` или `payload-ready` |

Для AEZAKMI и Journal Operator payload создаётся только для SHA-256-бинарников,
которые были статически проверены в этом наборе. Неизвестная или изменённая
сборка остаётся `candidate-review`; сканер сохраняет причину и не пишет
payload для неё. Ни один challenge ELF при проверке не запускается.

Для Wolf Protocol решатель допускает только ELF с известным SHA-256. В локальном
бинарнике байт ключа берётся как `(state >> 17) & 0xff`; вариант `>> 24` из
публичного write-up не восстанавливает флаг. Кандидат принимается только после
точного повторного кодирования всех 35 байтов target. Сам ELF не запускается.

`candidate` означает, что строка выведена из локального артефакта, но не
подтверждена платформой. `payload-ready` означает, что получен статический
материал для разрешённой копии сервиса; бинарник не запускается. Для сервисных
задач можно положить рядом с корнем файл вроде `backdoor.transcript` или
`pixelmart.log`: найденные в нём строки будут сохранены как
`transcript-derived` кандидаты. Такой статус означает, что значение извлечено
из сохранённого ответа авторизованного task-сервиса; это не сетевой запрос,
проверка платформой или автоматическая отправка.

В real-quals отчёте отдельно считаются `summary.quals_candidate_task_count`,
`summary.quals_payload_ready_count` и
`summary.quals_requires_session_count`; нераспознанный OCR выделяется в
`summary.quals_review_count`. Если в корне есть `ICO_full_walkthrough.md`, его
явно напечатанные исторические значения попадают отдельно в
`reference_candidates` со статусом `reference-only`; они не смешиваются с
локальными кандидатами и не считаются подтверждением текущего сервиса.
Поддерживается и формат архива ICO 2027: `ico_qualifying_round/ico_ctf_writeup.md`
распознаётся как отдельный quals-корень, а сам write-up исключается из общего
поиска кандидатов. Его ответы остаются `reference-only`; отсутствие challenge-
файлов и пропущенный автором флаг VIP Club не заполняются догадками.
Производные файлы находятся под
`report/artifacts/ico-quals/<task>/`, а исходные challenge-файлы не изменяются.

Публичный архив файлов отбора ICO 2027 можно передать напрямую, не распаковывая
его вручную:

```sh
ico-scan /path/to/ico2027_qualifying_files.7z
```

После ограниченного извлечения scanner распознаёт маркеры набора внутри архива,
запускает task-aware решатели до общего анализа вложенных файлов, сохраняет
quals-индекс в отчёте и печатает кандидаты и статусы задач. Исторические ответы остаются
`reference-only`; наличие архива само по себе не подтверждает флаг на платформе.

Для `Can you hear the flag?` решатель сохраняет обычную и дополнительную
спектрограмму в линейном окне 2–5 кГц, где текст на данном WAV читается заметно
яснее. Из сфокусированной спектрограммы он также создаёт OCR-представление:
обрезает область `4096×480` с координат `(0, 300)` и сжимает её до `4096×230`.
OCR-планировщик принимает эти представления и заранее названные task-derived
crops. Одинаковые изображения дедуплицируются по SHA-256, случайные соседние
PNG не выбираются, а на одну задачу приходится не более восьми вызовов
Tesseract. Сначала запускается PSM 7 на выбранных видах; PSM 6 используется
только для длинного вывода, а PSM 8 и 11 — как два ограниченных fallback-режима
для компактного crop. Для каждого вызова в `steps` записываются входной хэш,
причина выбора, PSM, длительность и согласие независимых изображений;
неоднозначный OCR остаётся `candidate-review`. Если OCR сохранил тело,
похожее на флаг, но потерял открывающую скобку, в `steps` появляется
`ocr-review` с исходной строкой и осторожной нормализацией. Длинные
hex-подобные строки с повреждённым префиксом сохраняются как исходная ручная
зацепка без догадки о префиксе; ни одна такая подсказка не становится
кандидатом автоматически.

Для полного набора автоматически создаётся индекс всех десяти задач:
`report/artifacts/ico-quals/answer-index/answers.json`, `answers.md`,
`answers.txt` и `solution-bundle.md`. Файл `answers.txt` содержит только
уникальные значения по одному на строку, чтобы их можно было сразу
скопировать. Разметка по задачам, локальные кандидаты, transcript-derived
значения, исторические значения, статусы решателей и следующие допустимые
шаги находятся в `answers.json`, `answers.md` и отчёте. Дополнительно
создаётся отдельный `historical-solution.md` в каталоге каждой задачи.
Поэтому локальный запуск показывает все доступные значения из walkthrough,
артефактов и transcript’ов, а не только флаги, извлечённые непосредственно из
бинарных и медиа-файлов.
Исторические значения остаются отдельным evidence state и не повышают
`candidate_count`; это позволяет получить полный offline-обзор набора, не
выдавая старый walkthrough за новый ответ платформы.

По умолчанию используются ограничители: глубина 3, 1 000 файлов, 100 MiB заявленного расширения архивов, 30 секунд на анализатор и 300 секунд на листинг/извлечение архива. Их можно изменить через `--max-depth`, `--max-files`, `--max-bytes`, `--timeout` и `--archive-timeout`. Для бинарных файлов больше 2 MiB общий XOR-проход пропускается, если в условии нет подсказки про XOR; задача с таким условием запускает его. Большие архивы обрабатываются частично: scanner извлекает только безопасные отдельные вложения в пределах лимита, пропуская крупные файлы, ссылки, небезопасные пути и превышение количества файлов. `report.json` сохраняет `selected_entries`, `skipped_entries` и признак `partial`, чтобы было видно, какой материал остался непроверенным. Для JPEG можно явно включить детерминированный режим StegSeek без словаря:

```sh
ico-scan image.jpg --allow-stegseek-seed
```

Сетевые запросы, сканирование портов, перебор флагов и автоматическая отправка
не выполняются. Для явно распознанной задачи SAM I AM профиль может проверить
NTLM-хэш по установленным локальным словарям в пределах заданного тайм-аута,
применяя небольшой фиксированный набор правил для регистра, цифр и знаков
препинания. Он автоматически ищет распространённые локальные словари, включая
`rockyou.txt`, John `password.lst` и `/usr/share/dict/words`, если они есть;
произвольный перебор паролей не запускается. Дополнительные словари можно
передать через `ICO_CTF_WORDLIST_PATHS`, разделив их системным разделителем
путей.

## Универсальный офлайн-реестр

Обычный `ico-scan` теперь подключает детерминированный реестр профилей для
данных/контейнеров, медиа и стеганографии, PCAP/SQLite/логов, криптографии,
статического reverse/pwn и сохранённых web/API-транскриптов. Профили запускаются
только при совпадении сигнатуры или условия и сохраняют `steps`, `artifacts` и
`candidates` в `report.json`. Статический reverse-профиль отмечает каждый шаг
`executed=false`. Общий PWN-анализатор сообщает `payload-ready` только если
создал конкретный ret2win payload из offset и адреса; сведения об опасном API
или диагностический format-string probe требуют `candidate-review` и не
считаются готовым эксплойтом. В task-aware AEZAKMI и Journal Operator payload
создаётся только для совпавших SHA-256 проверенных сборок. Неизвестный ELF
требует ручной проверки и не получает payload.

Для Mach-O инвентаризация также показывает CPU type и флаг PIE. Встроенные в
нативный файл строки, похожие на флаги, попадают в отчёт как непроверенные
подсказки (`verification=embedded-string-only`); совпадение с текстом внутри
бинарника само по себе не считается решением и может быть decoy. Для x86-64
ELF с Capstone этот статус повышается только если статический разбор связывает
строку с аргументом `strcmp`, а ветка равенства ведёт к сообщению об успехе и
другая ветка — к сообщению об ошибке (`verification=static-success-branch`).
Бинарник при этом не запускается, а кандидат не считается подтверждённым
платформой.
На macOS после неполного результата Tesseract включается резервный OCR через
Vision. Узкая коррекция `ictfE` → `ictf{` явно помечается как
`vision-ocr-corrected`; такой результат остаётся локальным кандидатом и не
отправляется на платформу.

Для PCAP/PCAPNG дополнительно разбираются TCP-потоки с JSONL-записями вида
`{"type":"file","path":"/guest/name","data":"<base64>"}`. Валидные
вложения сохраняются в `artifacts/universal-forensics/` и повторно ставятся в
общую очередь анализаторов. Пути гостевой системы не используются как пути
записи; извлечение ограничено общими лимитами размера и числа файлов, глубиной
очереди и каталогом текущего отчёта. Контекст исходной задачи сохраняется для
производных файлов.

Если рядом с захватом передан NSS/Wireshark TLS key log, forensics-профиль
сверяет client-random из ClientHello с ключами и, при совпадении, офлайн
дешифрует найденные TLS-потоки через установленный `tshark`. Направления
сохраняются как производные артефакты и повторно анализируются общей очередью.
При самостоятельном сканировании каталога профиль также ищет в той же папке
ограниченное число обычных файлов с именами `keylog`/`tls-key` и подходящими
расширениями; отдельный task manifest для такой пары не обязателен.
Для HTTP/2 отдельно сохраняются тела DATA-кадров и декодированные блоки HEADERS
в `tls-http2-headers.jsonl`; записи сохраняют номера TLS/HTTP2-потоков, URI,
порты и пары имя/значение заголовка, включая метод, путь, статус и авторизацию.
Поиск ограничен лимитами времени, размера и числа файлов; без подходящего
key log или `tshark` отчёт отмечает необходимость проверки, а не заявляет о
дешифровании.

Для `AETH`-карт с соседним `aethmap_sealer.py` crypto-профиль статически
проверяет поддерживаемую формулу через Python AST, не исполняя скрипт, и
использует публичный `vault_seal`, чтобы построить дешифрованный локальный
артефакт. Флаг из него остаётся кандидатом до проверки исходным checker-ом или
сервисом задачи.

Для локального публичного набора DownUnderCTF 2024 включены task-aware профили.
Macro Magic извлекает VBA из XLSM через `oletools` без запуска макроса,
выводит повторяющийся XOR-ключ из строковых присваиваний и проверяет числовые
URL из PCAP через офлайн `tshark`. SAM I AM читает только локальные SAM/SYSTEM
hive-файлы библиотекой Impacket и при наличии локального словаря проверяет
один Administrator NTLM-хэш через hashcat. Если словаря нет, отчёт сохраняет
хэш и причину пропуска. Three Line использует ограниченные crib-гипотезы и
выводит текст-кандидат только после восстановления полного ключа.
Number Mashing получает `payload-ready` только после проверки точного шаблона
ветвлений и инструкции AArch64 `SDIV`; вывод записывается в `.stdin`, но не
исполняется. Все найденные строки остаются локальными кандидатами, пока
исходный checker или платформа их не подтвердит.

Дополнительные hash-gated профили разбирают Rusty Vault (AES-GCM с проверкой
тэга), Adorable Encrypted Animal (восстановление ключа из пары контейнеров) и
Pressing Buttons (декодирование перестановок из IPA). Они дают локальные
кандидаты, а не подтверждение платформы. Dungeon и Vector Overflow готовят
проверяемые локальные маршруты/вводы со статусом `payload-ready`; бинарники и
сервисы при этом не запускаются. `Average Assembly Assignment` также пишет
полную кодированную программу; `sign in` сохраняет шесть шагов, основанных на
статически проверенной раскладке памяти. Эти артефакты не содержат флаг и не
обращаются к challenge-сервису.

Для точного исходника DUCTF `V for Vieta` сканер сохраняет
`v-for-vieta-session-solver.py`. Для каждого JSON-раунда он берёт квадратный
корень `r = isqrt(k)`, строит `b = 2*r^3-r` и второй корень
`a = (2*k-1)*b-r`, затем точно проверяет исходное уравнение и лимит 2048 бит.
Скрипт читает JSON-строки из stdin и печатает ответы в stdout; сетевого клиента
в нём нет. Поскольку реальные `k` и `FLAG` задаются только запущенным сервисом,
задача получает статус `requires-authorized-session`, а
`summary.challenge_requires_authorized_session_task_count` учитывает её
отдельно от ручного review и от локально найденных кандидатов. Встроенный
placeholder из исходника не считается флагом.

Сохранённый HAR, cURL или raw HTTP можно передать как обычный файл:

```sh
ico-scan capture.har --out ./report
```

Такой проход разбирает запросы и ответы, query/form/JSON-параметры, cookies,
redirects, JWT payload и ограниченные вложенные кодировки. Для WordPress REST
ответов он сохраняет увиденные namespaces и route/method/argument metadata; в
запросах к `wp2shell` поле `c` только декодируется в отчёт, команда не запускается.
Парсер работает по сохранённому файлу и не делает новый сетевой запрос. Для
отдельного тестового локального сервиса существует `ico_active.AuthorizedClient`:
хост должен быть явно указан в
`TargetPolicy.allowed_hosts`, бюджет запросов ограничен, а `cyberolympiad.kz` и
его поддомены всегда блокируются. Этот клиент не используется CLI автоматически.

Матрицу регрессии локальных наборов можно получить без сети:

```sh
python3 scripts/run_corpus_matrix.py \
  $ICO_CTF_STARTER_ROOT \
  $ICO_CTF_REAL_ROOT \
  $ICO_QUALS_ROOT \
  --out ./corpus-matrix
```

`corpus-matrix.json` содержит хэши исходных файлов, длительность, состояния
решателей, уникальные ответы и проверку, что исходный корпус не изменился.
Формат матрицы имеет `schema_version: 2`. В каждой строке `metrics` отдельно
считаются `current_candidates`, `hash_verified`, `transcript_derived`,
`payload_ready`, `needs_review`, `session_required`, исторические ссылки,
ошибки/таймауты инструментов и `coverage` по task-root, семейству и сложности.
Пропуски отсутствующих optional-инструментов не считаются ошибками.

Для заявленной структуры финального отбора есть локальная synthetic-матрица:
три истории × пять семейств (`web`, `pwn`, `forensics`, `reverse`, `crypto`) ×
три уровня (`easy`, `medium`, `hard`) плюс пять отрицательных fixtures. Это
регрессионный corpus поддержанных преобразований, а не обещание решить любую
неизвестную live-задачу. Его можно пересоздать и проверить так:

```sh
python3 scripts/generate_story_matrix.py
python3 -m unittest tests.test_ico_universal_integration -v
python3 scripts/run_corpus_matrix.py benchmarks/ico_story_matrix \
  --out ./ico-scan-runs/story-matrix
```

Матрица ожидает 45 положительных case roots и пять negative roots. Для web
значения отмечаются как `transcript-derived`, для детерминированных offline
преобразований как `candidate`, а статический pwn/reverse материал без флага как
`payload-ready`. Negative fixtures должны оставаться без candidate.

Для отдельной проверки формата финала есть детерминированный набор из 50 задач:
10 историй × 5 категорий (`web`, `pwn`, `forensics`, `reverse`, `crypto`).
Ожидаемые ответы лежат только во внешнем hash-manifest; они не входят в
каталог, который читает solver. Генерация, решение и независимый scorecard:

```sh
python3 scripts/generate_final_benchmark.py --round 1
./ico-solve benchmarks/ico_final_50 --mode fast --workers 4 \
  --deadline 120 --debug ico-final-runs/round-01
python3 scripts/score_final_benchmark.py \
  --report ico-final-runs/round-01/report.json \
  --manifest benchmarks/ico_final_50.expected.json \
  --corpus benchmarks/ico_final_50 \
  --out ico-final-runs/round-01/scorecard.json
```

Score `10/10` означает ровно `50/50` hash/checker-verified задач, полный
набор task IDs и ноль false positives. `candidate`, `candidate-review` и
`payload-ready` считаются прогрессом, но не точным решением. Все артефакты
этого набора синтетические и офлайн; это измерение toolkit, а не прогноз
реального финала.

После доказанного `50/50` можно создать ровно один усложнённый раунд. Gate
fail-closed и ничего не создаёт при неполном score:

```sh
python3 scripts/evolve_final_benchmark.py \
  --scorecard ico-final-runs/round-01/scorecard.json \
  --round 1 --output-root benchmarks
```

Каждый следующий раунд сохраняет 50 задач, меняет seed и добавляет слои/
декои к evidence. Внешний scorer нужно запускать заново для каждого раунда;
бинарники и сервисы задач не запускаются.

Для стресс-проверки решателя есть отдельный профиль `hardest`. В нём все 50
подзадач имеют уровень `hard`, а evidence проходит через семейный этап и
многошаговую цепочку: nonce-derived key, rolling transform, byte rotation,
seeded permutation, zlib, base85 и фрагментацию. Для каждой задачи создаются
шесть правдоподобных декоев; контрольный digest разделён между файлами
`chain.json` и `checksum.txt`. Контейнеры отличаются по семействам (NDJSON,
ELF-like static blob, carve stream, VM trace и crypto bundle), но challenge
артефакты остаются офлайн и не исполняются:

```sh
python3 scripts/generate_final_benchmark.py --round 1 --profile hardest
./ico-solve benchmarks/ico_final_50_hardest_round_01 --mode fast --workers 4 \
  --deadline 120 --debug ico-final-runs/hardest-round-01
python3 scripts/score_final_benchmark.py \
  --report ico-final-runs/hardest-round-01/report.json \
  --manifest benchmarks/ico_final_50_hardest_round_01.expected.json \
  --corpus benchmarks/ico_final_50_hardest_round_01 \
  --out ico-final-runs/hardest-round-01/scorecard.json
```

Следующий hard-раунд создаётся только из точного `50/50`:

```sh
python3 scripts/evolve_final_benchmark.py \
  --scorecard ico-final-runs/hardest-round-01/scorecard.json \
  --round 1 --profile hardest --output-root benchmarks
```

Для непрерывного цикла есть bounded-runner. Он решает и независимо оценивает
каждый раунд, после каждого точного `50/50` создаёт следующий более сложный
корпус и продолжает работу; при первом нарушении gate останавливается. После
`--max-rounds` последний успешный successor уже создан, поэтому цикл можно
безопасно продолжить следующей командой с его номером:

```sh
python3 scripts/run_final_benchmark_cycle.py \
  --start-round 1 --max-rounds 3 --profile hardest \
  --output-root benchmarks --run-root ico-final-runs/cycle
```

Итог каждого запуска сохраняется в `ico-final-runs/cycle/cycle-summary.json`.
В summary отдельно записаны измеренные scorecard и созданные successor-корпуса;
`score-gate` или `evolution-gate` означает, что новый раунд не был создан.

Проверить доступность только тех optional-инструментов, которые упоминаются
активными профилями, можно без запуска полного scan:

```sh
python3 scripts/check_toolchain.py
```

## Установленные группы

- **Файлы и стеганография:** `binwalk`, `exiftool`, `pngcheck`, `zsteg`, `steghide`, `stegseek`, `foremost`, `7zz`, `qpdf`, CyberChef 11.5.0.
- **Реверс и pwn:** Ghidra 12.1.2, Cutter 2.4.1, radare2 6.1.4, `gdb`, `pwntools`, `angr`.
- **Криптография:** `RsaCtfTool`, PyCryptodome, SymPy, Z3.
- **Форензика и сеть:** Sleuth Kit, Volatility 3 (`vol`), Wireshark/TShark, YARA, `jq`, `ffmpeg`. Для файлов с признаками memory dump запускаются offline-профили Volatility 3.
- **Web/API-задачи:** `ffuf`, `feroxbuster`, `gobuster`, `sqlmap`, `nmap`, mitmproxy, OWASP ZAP, Burp Suite Community.

Проверка основных бинарников:

```sh
source ./env.sh
binwalk --version; pngcheck -V; zsteg --version
stegseek --version; steghide --version
python -c 'import pwn, angr, Crypto, sympy; print("Python CTF stack: OK")'
rsactftool --help >/dev/null && vol -h >/dev/null && echo 'Python tools: OK'
```

## Внешние CTF-ресурсы

- [`ljagiello/ctf-skills`](https://github.com/ljagiello/ctf-skills) — MIT-набор
  методик для web, pwn, crypto, reverse engineering и forensics. Это полезная
  база процедур и команд для анализа незнакомых задач.
- [`0ca/BoxPwnr`](https://github.com/0ca/BoxPwnr) — AGPL-3.0 стенд для сравнения
  LLM-агентов на CTF-платформах и локальных заданиях; публикует трассы решений.
  Он подходит для отдельной agentic-оценки и изучения последовательности
  действий, а не как детерминированный профиль `ico-scan`.

Эти источники расширяют справочные и тестовые материалы, но их опубликованные
проценты решённых задач не являются оценкой ICO-финала. Для прогноза важны
локальная проверка конкретных файлов, ответ task-сервиса и подтверждение
платформой.

## Ограничения набора

SageMath не устанавливался: в текущем Homebrew нет формулы, а полноценная установка велика и не нужна для базового набора. Autopsy также не ставился нативно; его CLI-основа Sleuth Kit уже установлена. Kali/Parrot намеренно не скачивались, потому что это отдельные ОС и дублируют установленный macOS-набор. StudyLab не изменялся.

Инструменты перебора паролей присутствуют как стандартные CTF-зависимости, но их следует применять только когда восстановление секрета прямо предусмотрено условием. Перебор или угадывание флагов и сканирование инфраструктуры олимпиады запрещены правилами.
