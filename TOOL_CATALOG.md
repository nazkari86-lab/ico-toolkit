# ICO-Solve: расширенный каталог инструментов

Дата ревизии: 28 сентября 2026. Каталог составлен по официальным README и
репозиториям проектов, а не по одному списку Kali. В реестре `ico-solve`
сейчас 97 записей: 94 инструмента доступны нативно, 2 имеют помеченный
macOS compatibility backend и 1 отсутствует в текущем окружении;
доступность проверяется заново после `source env.sh`.
Инструмент считается подключённым только после проверки его CLI или Python-
модуля в текущем окружении.

Автоматический pipeline использует эти компоненты совместно: ограниченно
собирает файлы, созданные профилями carving/decompilation, заново определяет
тип каждого файла и запускает подходящие офлайн-анализаторы следующими волнами.
В `ico-solve --mode full` рекурсивная часть ограничена глубиной 3, 200 файлами,
100 MiB суммарных входных данных и 120 секундами, дедуплицирует SHA-256 в
рамках задачи и сохраняет provenance. Сессионные, сетевые и benchmark-проекты
остаются в отдельных режимах и не выдаются за file-only интеграции.

Полезные идеи из проектов плана перенесены в общую механику решателя:

| Источник идеи | Что делает ICO Toolkit в ядре |
| --- | --- |
| Unblob и Binwalk | Распознаёт вложенные форматы, извлекает данные с лимитами и подаёт полученные файлы на повторную классификацию. |
| Binary Refinery и CyberChef Magic | Применяет ограниченные декодеры и цепочки преобразований; Base58/Base85 можно обнаружить без подсказки, но выход принимается только при сильном сигнале. |
| Katana и Aperi'Solve | Использует отдельные анализаторы как workers с результатами и производными файлами в общей очереди, а не как независимые команды из каталога. |
| RsaCtfTool, crypto-attacks, Z3 и angr | Сначала проверяет условия применимости специализированного алгоритма, ограничивает запуск и подтверждает математический результат точной проверкой. |
| Ghidra, FLOSS и capa | Выполняет статический разбор локальных бинарников; строки, структура и дочерние артефакты продолжают проходить общий цикл анализа. |
| TShark, Volatility, Dissect и The Sleuth Kit | Разбирает только подходящие сетевые, memory- и disk-артефакты и сохраняет происхождение каждого извлечённого результата. |
| Планировщики этих проектов | Сначала запускает быстрые и профильные workers, затем тяжёлые; ошибки отдельного worker-а не останавливают остальные. При общем deadline часть времени сохраняется для adapter-слоя, а неизменённые файлы повторно используют classification по path/hash. |

Практический пример сквозной передачи: CyberChef преобразует ROT13-текст в
Base64, затем сохраняет распознанный ZIP с описанием transform chain; тот же
ZIP поступает в универсальный solver и его содержимое проходит обычные
forensics-профили. Выход необязательного инструмента становится полезным только
когда его можно воспроизвести, ограничить и связать с исходным файлом.
Условие, в котором названы два разных криптографических преобразования,
также позволяет `CryptoSolver` сохранить промежуточный результат и передать
его общему pipeline (проверено на `ROT13 → Base64 → flag`). Это regression-
fixture, а не подтверждённый прирост на историческом holdout: в локальных
ICO 2025/квалификационных условиях такое сочетание не встретилось.

На 25-task ICO 2025 корпусе с `--deadline 180` исходный режим оставил все 180 s
scanner-у: 171 из 230 adapter-запусков не успели начаться. После разделения
бюджета fast-режим завершился за 143.9 s, запустил 230 adapters (224 `ok`, 6
`nonzero`) и сохранил те же 16 кандидатов без ошибок. Этот корпус не добавил
новых кандидатов; замер подтверждает исправленную передачу времени, а не прирост
решаемости. Base58/Base85 и CyberChef handoff отдельно проверены на
воспроизводимых сквозных фикстурах.

## Новые подключённые компоненты

Эти компоненты уже внесены в `ico_tool_adapters.py` и отображаются в
`ico-solve --tools`.

| Инструмент | Класс | Что добавляет | Режим |
| --- | --- | --- | --- |
| `checksec` | PWN | RELRO, Canary, NX, PIE и Fortify за один проход | автоматически для ELF/PE |
| `ROPgadget` | PWN | гаджеты на x86/ARM/MIPS/RISC-V и других поддержанных архитектурах | статически для бинарника |
| `ropper` | PWN | гаджеты, символы, stack pivot и сведения о формате | статически для бинарника |
| `objdump`, `nm` | Reverse | секции, строки, символы и дизассемблирование | статически |
| `otool`, `lldb` | Reverse | Mach-O load commands, библиотеки и список модулей без запуска | статически |
| `upx` | Reverse | обнаружение и инвентаризация UPX-паковки | только `-l`, распаковка не включена |
| `angr` + `angr-symbolic` | Reverse | статическое дизассемблирование и восстановление stdin для checker-бинарников | `--mode full`: ≤64 байт/96 states/48 s с success/failure сигналами; opt-in `--aggressive`: ≤256 байт/768 states/150 s для малых распознанных бинарников |
| Ghidra Headless | Reverse | анализ, извлечение строк и ограниченная декомпиляция локальных PE/ELF/Mach-O | `--mode full`, ≤64 MiB, ≤96 функций, проект удаляется после анализа |
| `unicorn` | Reverse | multi-architecture CPU emulation library | доступен как Python-модуль |
| `qiling` | Reverse | OS-aware cross-architecture emulation | extra-runtime, `qiling --probe`; не auto-run |
| `lief` | Reverse | структурный разбор PE/ELF/Mach-O | только если установлен |
| `fls`, `mmls`, `icat`, `tsk_recover` | Disk forensics | файловая система, таблица разделов и bounded recovery из образов | офлайн |
| `oleid`, `olevba`, `mraptor` | Office forensics | OLE/VBA извлечение, декодирование и риск-маркеры макросов | офлайн |
| `giftext` | Media forensics | GIF-комментарии, extension-блоки и frame metadata | офлайн |
| `sox` | Audio forensics | sample rate, каналы, статистика и повреждённые участки | офлайн |
| `apktool`, `jadx` | Mobile reverse | Manifest/smali и DEX→Java | bounded output в debug-каталог |
| `semgrep` | Source triage | локальные regex-правила для секретов и flag-shaped строк | только bundled rule, без registry |
| `trufflehog` | Source triage | локальный high-entropy/credential поиск | `--no-update`, без verification |
| `gitleaks` | Source triage | локальное обнаружение секретов | `--no-git`, без отправки |
| `scalpel` | Forensics | configurable file carving | bundled arm64 build, bounded profile |
| `strace` | PWN | syscall trace for an explicitly authorized local replica | native or macOS `dtruss-compat`; manual-only |
| `ltrace` | PWN | library-call trace for an explicitly authorized local replica | native or macOS `dtruss-compat`; manual-only |
| `unblob` | Forensics | рекурсивная распаковка firmware и вложенных контейнеров | `ico-solve --mode full`; input ≤128 MiB, output ≤256 MiB / 4096 entries / 110 s |
| `Binary Refinery` | Transform | преобразование бинарных и кодированных потоков | default: `b32`/`b58`/`b64`/`b85`/`hex`/URL; `--aggressive`: Base62/Base92/Base65536/Z85, UU, UTF-16, reverse, bit/byte reverse и decompression; команды идут через bounded `ico-refinery` wrapper |
| `RsaCtfTool` | Crypto | восстановление plaintext из рядом лежащего RSA-шифротекста | default: набор быстрых офлайн-атак; `--aggressive`: локальный `--attack all` с ограниченным временем; только при связке ключа и ciphertext, без FactorDB/WolframAlpha |
| `rsa-coppersmith` | Crypto | low-exponent RSA small-root recovery при известном префиксе | `--mode full`; требует явно заданные `n/e/c`, prefix и длину неизвестного хвоста; LLL в отдельном analysis runtime, точная проверка повторным шифрованием |
| `FLOSS` | Reverse | извлечение статических и декодируемых строк | bounded static profile для executable-файлов |
| `capa` | Reverse | классификация возможностей PE/ELF/shellcode | bounded static profile; отчёт не равен решению задачи |
| `Dissect target-qfind` | Disk forensics | поиск flag-prefix в дисковом артефакте, включая UTF-16LE/raw regions | `ico-solve --mode full`, до 4 GiB; результат остаётся кандидатом |
| `StegSeek` | Stego | распознавание и извлечение незашифрованного steghide payload по embedding pattern | JPEG-only `--seed`, без wordlist; извлечённый файл проходит общий bounded pipeline |

В текущий extra-runtime также установлены `stegoveritas`, `xortool`, `hashid`,
`hashpumpy` и официальные `pdfid`/`pdf-parser.py` из
[DidierStevensSuite](https://github.com/DidierStevens/DidierStevensSuite).
Они доступны после `source env.sh`; несовместимые legacy-зависимости вынесены
в отдельные venv-обёртки.

Frida и Objection тоже видны в инвентаре, но требуют явно подключённого
локального процесса или устройства и поэтому не запускаются самим `ico-solve`.
FactorDB отмечен как сетевой и также не запускается автоматически.

## Дополнительные инструменты, установленные 28 сентября

| Инструмент | Версия/источник | Автоматический режим | Ограничение |
| --- | --- | --- | --- |
| AFL++ | Homebrew 5.03c | нет | только ручной fuzzing в изолированной sandbox; toolkit не запускает challenge-бинарники |
| Nuclei | Homebrew 3.11.1 + официальный шаблонный набор | нет | активные проверки только по явному allowlist локальной/разрешённой цели |
| Arjun | PyPI 2.2.7 в `ico-analysis-venv312` | нет | только локальная задача или разрешённая replica; не вызывается file-only pipeline |

Повторяемая установка: `scripts/install_optional_active_tools.sh`. Она ставит
эти утилиты и обновляет локальные Nuclei templates, но не запускает сканирование
цели. SageMath — единственный отсутствующий пункт инвентаря. Проверка Homebrew
28 сентября 2026 вернула `No Cask with this name exists`; раньше записанное
утверждение о доступном cask было неверным. Установка SageMath не выполнялась.
`fpylll==0.6.4` и `sympy==1.14.0` доступны только в `ico-analysis-venv312`;
теперь там есть узкий Coppersmith-профиль для явно заданных известных RSA
префикса и длины хвоста. Это не универсальный решатель lattice-задач.

## Установленные дополнения этого прохода

Следующие утилиты запускаются через `bin/`-обёртки. Обёртки изолируют старые
Python-пакеты и Ruby/Go-сборки; они не меняют поведение решателя и не включают
сетевые профили автоматически.

| Инструмент | Источник/сборка | Проверка | Ограничение |
| --- | --- | --- | --- |
| `Ciphey` | PyPI 5.14.0 + локально собранный `vendor/CipheyCore` (arm64) | `ciphey --help`, Base64 smoke | default по явному encoded-сигналу; `--aggressive` для bounded printable blobs, без сети |
| `FeatherDuster` | NCC Group legacy Python 2 project | not installed into the solver runtime | interactive Python 2 workbench; no reliable non-interactive CLI, so not invoked automatically |
| `peepdf` | PyPI 0.4.2 в отдельном `ico-peepdf-venv314` | `peepdf --help` | PDF static/manual mode (`-m`), без VirusTotal |
| `hashpumpy` | PyPI 1.2 + `bin/hashpumpy` CLI | `hashpumpy --help` | length-extension по известному digest; ключи не перебираются |
| `one_gadget` | Ruby gem 2.1.1 | `one_gadget --help` | только локальная предоставленная libc |
| `seccomp-tools` | Ruby gem 1.7.1 | `seccomp-tools --help` | static BPF inspection; `dump` не запускается решателем |
| `clairvoyance` | PyPI 2.5.5 в отдельном `ico-graphql-venv314` | `clairvoyance --help` | только local replica/transcript |
| `graphql-cop` | официальный `dolevf/graphql-cop`, pinned commit | `graphql-cop --help` | только local replica/transcript |
| `graphw00f` | официальный `dolevf/graphw00f`, pinned commit | `graphw00f --help` | только local replica; PyPI placeholder не используется |
| `jwt_tool` | официальный `ticarpi/jwt_tool`, pinned commit | `jwt_tool --help` | сохранённый JWT/HAR или local replica |
| `kiterunner` (`kr`) | официальный `assetnote/kiterunner`, локальная Go-сборка arm64 | `kr --help` | только local replica; сканирование не запускается автоматически |

Qiling проверяется через arm64 Keystone из Homebrew и extra-runtime;
`qiling --probe` должен вывести `state=available`. Scalpel собирается
`scripts/build_scalpel.sh` против Homebrew TRE с C++98-совместимым режимом,
после чего `scalpel-carve` запускается только на локальных входных файлах.
`strace` и `ltrace` на macOS представлены честным `dtruss-compat` backend;
он не эквивалентен Linux library tracing и требует явного
`ICO_ALLOW_COMPAT_TRACE=1`. PyPI-пакет с именем `graphw00f` удалён:
используется только официальный репозиторий.

Для опциональных анализаторов добавлен повторяемый установщик
`scripts/install_optional_solver_tools.sh`. Он держит Python 3.12 stack
(Refinery, FLOSS, capa, Dissect, fpylll, SymPy, Ropper и Semgrep) отдельно от основного
runtime и ставит Unblob в совместимый extra-runtime. Перечень версий хранится в
`requirements-optional-analysis.txt`, `requirements-optional-unblob.txt` и
`requirements-optional-angr.txt`. angr/Claripy/Z3 устанавливаются отдельно от
Python 3.14 и анализа с fpylll.
Наличие библиотеки в virtualenv не означает, что для неё уже есть подходящий
автоматический solver: например, `fpylll` требует задачу, где из условия
выводятся корректная решётка, размер и ограничения на коэффициенты.

## Что произошло с 31 пунктом первоначального плана

Katana — реальный автоматический CTF checklist-решатель, а не просто пример
архитектуры. Его README одновременно предупреждает, что проект слабо
поддерживается, а запуск может выполнять активные web-проверки, включая SQLi,
LFI, загрузку shell и попытки RCE; его legacy setup также тянет много тяжёлых
зависимостей. Поэтому целиком подключать его в offline file pipeline нельзя.
После сверки его локальных модулей в `CryptoSolver` добавлены собственные
детерминированные декодеры Morse, NATO-фонетики, T9 multi-tap, Atbash, ROT47 и
Rail Fence. Они включаются только по явной подсказке и используют только
переданные данные; неизвестные ключи/число рельсов не перебираются.

Остальные проекты исходного плана распределены ниже по фактической роли:
автоматические профили, ручные/сессионные инструменты, benchmark-архивы или
неподходящие для file-only режима. Установка и наличие ссылки сами по себе не
считаются интеграцией решающей способности.

| № | Проект из плана | Текущее решение |
| ---: | --- | --- |
| 1 | Unblob | активен в `full`, ограничен по глубине, суммарному выводу, числу файлов и времени |
| 2 | Binary Refinery | активны распознанные Base32/Base58/Base64/Base85/hex/URL-профили; каждый проходит через bounded `ico-refinery` wrapper |
| 3 | CyberChef | локальный набор быстрых преобразований уже встроен; Magic не запускается как безлимитный поиск цепочек |
| 4 | Katana | не запускаем целиком: старый checklist-автоматизатор может выполнять активные web-атаки; собственные offline-порты уникальных безопасных текстовых операций теперь есть в `CryptoSolver` |
| 5 | RsaCtfTool | запускает только `cube_root`, `wiener`, `fermat`, `smallq`, `pollard_p_1` при наличии RSA-ключа и соседнего ciphertext; сетевые атаки исключены |
| 6 | SageMath | Homebrew не находит cask `sagemath`; пакет не установлен, альтернативный macOS-пакет и его размер не подтверждены |
| 7 | Z3 | CLI 5.1.0 используется для `my-array`; отдельный angr-runtime содержит pinned Python bindings. Автоматическая SMT-постановка всё ещё task-specific |
| 8 | [`crypto-attacks`](https://github.com/jvdsn/crypto-attacks) | Håstad broadcast и RSA shared-prime batch-GCD реализованы как bounded offline solvers; каждый результат проходит точную проверку повторным RSA-шифрованием; новые атаки переносить по подтверждённым пробелам |
| 9 | fpylll | доступен в отдельном runtime; добавлен bounded RSA Coppersmith-профиль для явных `n/e/c`, known prefix и длины неизвестного хвоста; прочие lattice-схемы не реализованы |
| 10 | John the Ripper | доступен как ручной инструмент для локальных артефактов; без автоматического перебора паролей |
| 11 | Ghidra | автоматический headless-профиль извлекает строки и до 96 функций; проверен на локальном Mach-O fixture, бинарник не запускается |
| 12 | angr | pinned `angr==9.2.223`, Claripy и Z3 установлены в `ico-angr-venv312`; в `full` добавлен bounded stdin solver для локальных checker-бинарников с явными success/failure строками. Положительный x86_64 ELF fixture выдал точный ввод; Darwin ARM64 variadic `scanf` закрывается как unsupported. Кандидат не равен ответу checker-а или платформы |
| 13 | FLOSS | активен в bounded static профиле |
| 14 | capa | активен в bounded static профиле |
| 15 | LIEF | уже используется встроенным read-only адаптером для PE/ELF/Mach-O |
| 16 | pwntools | установлен для локальной сборки payload; запуск против удалённых целей не входит в file-only режим |
| 17 | AFL++ | установлен; только ручной isolated fuzzing, без автоматического запуска бинарников |
| 18 | pwndbg | интерактивная отладка в отдельной sandbox, не автоматический профиль |
| 19 | ROPgadget | активен для соответствующих бинарников |
| 20 | Volatility 3 | активен для memory dump и офлайн-плагинов |
| 21 | Wireshark/TShark | активен для PCAP-профилей |
| 22 | Dissect | `target-qfind` автоматически ищет распространённые флаговые маркеры в disk images |
| 23 | Binwalk | активен как профиль сигнатур/встроенных объектов; Unblob дополняет его рекурсивным извлечением |
| 24 | zsteg | активен для PNG/BMP |
| 25 | Stegseek | автоматический JPEG `--seed` профиль распознаёт незашифрованные embedding patterns; wordlist/password-cracking режим не запускается |
| 26 | Aperi'Solve | изучение архитектуры; сторонний upload-service не используется |
| 27 | ffuf | только явно разрешённая локальная web-реплика |
| 28 | sqlmap | только локальная реплика и конкретный web-сигнал |
| 29 | SecLists | не загружать целиком и не включать слепые словарные переборы |
| 30 | ICO 2025 архив | использовать как regression/holdout source с зафиксированным commit, не как новый runtime tool |
| 31 | Cybench | benchmark corpus, не инструмент решения; запускать отдельно от обучения и ответов |

Поэтому в плане перечислено много GitHub-проектов, но они имеют разный статус:
часть запускается автоматически на подходящих файлах, часть предназначена для
ручной работы с локальной сессией, а некоторые являются интерфейсом или набором
тестовых задач. Например, Trawl — браузерное Rust/WASM-приложение без CLI; его
web-crawler-режим требует сеть. Cybench — benchmark, а не решатель. Добавлять их
в file-only pipeline как команды было бы фиктивной интеграцией. Остальные
автономные проекты подключаются после проверки уникального поведения и точности
на корпусе, а не только по наличию ссылки или успешному `--help`.

## Лучшие новые уникальные кандидаты для следующего слоя

Это не обещание автоматического решения каждой задачи. Каждый пункт закрывает
свой класс, которого нет у обычной связки `strings + binwalk + CyberChef`.

| Приоритет | Проект | Уникальная ценность | Как подключать |
| ---: | --- | --- | --- |
| 1 | [Trawl](https://github.com/Yuv1s/Trawl) | единый локальный Rust/WASM pipeline для файлов, stego, текста и результата; файлы не загружаются | использовать как отдельный GUI/контрольный second opinion; ядро не дублировать без измерения |
| 2 | [angr](https://github.com/angr/angr) | symbolic execution, CFG, IR и data-dependency анализ | уже подключён; для конкретного бинарника запускать с условием/функцией из задания |
| 3 | [Qiling](https://github.com/qilingframework/qiling) | emulation с OS/API-слоем для ARM/MIPS/Windows firmware | extra-runtime probe проходит; ручной запуск |
| 4 | [Unicorn](https://github.com/unicorn-engine/unicorn) | лёгкая CPU-эмуляция shellcode и фрагментов без запуска ELF | Python adapter по известной архитектуре и адресу входа |
| 5 | [LIEF](https://github.com/lief-project/LIEF) | единый парсер PE/ELF/Mach-O и безопасное чтение load commands | Python adapter для структурных аномалий и секций |
| 6 | [oletools](https://github.com/decalage2/oletools) | VBA, OLE и DDE следы, которые не видны `strings` | уже подключён для Office-файлов |
| 7 | [The Sleuth Kit](https://github.com/sleuthkit/sleuthkit) | inode, deleted files, partitions и timelines из disk image | `fls`/`mmls`/`icat`/`tsk_recover` подключены офлайн |
| 8 | [stegoveritas](https://github.com/bannsec/stegoveritas) | много независимых image-stego transforms и colour-plane анализов | подключённый офлайн-профиль с bounded output |
| 9 | [bulk_extractor](https://github.com/simsong/bulk_extractor) | потоковое извлечение email/URL/карточных и иных features из больших образов | bounded disk-forensics worker; не запускать на огромном E01 без storage gate |
| 10 | [XORtool](https://github.com/hellman/xortool) | оценка длины ключа и crib-guided repeating-key XOR | только при условии про XOR; не использовать для перебора флага |
| 11 | [HashPump](https://github.com/bwall/HashPump) | length-extension для MD5/SHA-1/SHA-256/SHA-512 | payload builder по известному digest/формату, без онлайн submit |
| 12 | [Ciphey](https://github.com/Ciphey/Ciphey) | автоматическое распознавание цепочек кодировок/классических шифров | подключён через arm64-built CipheyCore в отдельном venv |
| 13 | [hashID](https://github.com/psypanda/hashID) | классификация семейства хэша до выбора solver-а | дешёвый text profile |
| 14 | [pdf-parser](https://github.com/DidierStevens/DidierStevensSuite) и [peepdf](https://github.com/jesparza/peepdf) | object streams, JavaScript и embedded PDF payloads | read-only PDF profiles, peepdf manual mode |
| 15 | [seccomp-tools](https://github.com/david942j/seccomp-tools) | дизассемблирование и визуализация seccomp BPF | static PWN profile; бинарник не запускается |
| 16 | [one_gadget](https://github.com/david942j/one_gadget) | поиск libc `execve` gadgets | применять к предоставленной libc, не к удалённому сервису |
| 17 | [pwndbg](https://github.com/pwndbg/pwndbg) | современная GDB визуализация heap/stack/regs | интерактивная помощь в локальном sandbox; не auto-run |
| 18 | [Frida](https://github.com/frida/frida) + [Objection](https://github.com/sensepost/objection) | динамический Android/iOS tracing и runtime hooks | только явно разрешённая локальная app/device session |
| 19 | [jwt_tool](https://github.com/ticarpi/jwt_tool) | JWT header/claims/algorithm audit | только сохранённый JWT/HAR или local replica |
| 20 | [Arjun](https://github.com/s0md3v/Arjun) и [Kiterunner](https://github.com/assetnote/kiterunner) | скрытые HTTP-параметры и API route discovery | только local replica; удалённые ICO-хосты заблокированы |
| 21 | [graphql-cop](https://github.com/dolevf/graphql-cop) и [clairvoyance](https://github.com/nikitastupin/clairvoyance) | GraphQL audit и schema inference при отключённой introspection | только transcript/local endpoint |
| 22 | [Nuclei](https://github.com/projectdiscovery/nuclei) | воспроизводимые template checks | установлен с templates; только явно разрешённая local replica, не платформа ICO |

## Что не стоит добавлять как автоматический default

`nmap`, `ffuf`, `feroxbuster`, `gobuster`, `sqlmap`, Hydra, John, Hashcat,
Frida, Objection, Arjun, Kiterunner, GraphQL scanners и Nuclei меняют состояние
или требуют сетевой/сессионной цели. Они могут быть полезны на локальном стенде,
но запускать их вслепую по файлу или по ICO-платформе неправильно. В инвентаре
они остаются с явной отметкой `local-only` и `offline_default=false`.

## Дублирование и порядок запуска

1. `ico-solve --mode fast` запускает дешёвые статические профили и встроенные
   декодеры.
2. `--mode full` добавляет OCR, carving, decompilation и тяжёлый reverse.
3. Сначала task-aware solver и структурные анализаторы, затем generic profiles.
4. Один и тот же flag-shaped текст не считается доказанным: candidates,
   payload-ready и platform-confirmed сохраняются раздельно.

Источники для общей матрицы: [Trawl README](https://github.com/Yuv1s/Trawl),
[angr README](https://github.com/angr/angr), [Unicorn README](https://github.com/unicorn-engine/unicorn),
[Qiling README](https://github.com/qilingframework/qiling),
[Awesome CTF](https://github.com/apsdehal/awesome-ctf) и
[CTF toolkit topic](https://github.com/topics/ctf-toolkit).
