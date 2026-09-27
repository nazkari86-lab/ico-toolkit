# ICO-Solve: расширенный каталог инструментов

Дата ревизии: 27 сентября 2026. Каталог составлен по официальным README и
репозиториям проектов, а не по одному списку Kali. В реестре `ico-solve`
сейчас 87 инструментов; доступность проверяется заново после `source env.sh`.
Инструмент считается подключённым только после проверки его CLI или Python-
модуля в текущем окружении.

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
| `angr` | Reverse | дизассемблирование и symbolic-execution tooling | bounded CLI, бинарник не исполняется |
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

В текущий extra-runtime также установлены `stegoveritas`, `xortool`, `hashid`,
`hashpumpy` и официальные `pdfid`/`pdf-parser.py` из
[DidierStevensSuite](https://github.com/DidierStevens/DidierStevensSuite).
Они доступны после `source env.sh`; несовместимые legacy-зависимости вынесены
в отдельные venv-обёртки.

Frida и Objection тоже видны в инвентаре, но требуют явно подключённого
локального процесса или устройства и поэтому не запускаются самим `ico-solve`.
FactorDB отмечен как сетевой и также не запускается автоматически.

## Установленные дополнения этого прохода

Следующие утилиты запускаются через `bin/`-обёртки. Обёртки изолируют старые
Python-пакеты и Ruby/Go-сборки; они не меняют поведение решателя и не включают
сетевые профили автоматически.

| Инструмент | Источник/сборка | Проверка | Ограничение |
| --- | --- | --- | --- |
| `Ciphey` | PyPI 5.14.0 + локально собранный `vendor/CipheyCore` (arm64) | `ciphey --help`, Base64 smoke | ручной bounded decoder, без ICO-сети |
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
| 22 | [Nuclei](https://github.com/projectdiscovery/nuclei) | воспроизводимые template checks | только явно разрешённая local replica, не платформа ICO |

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
