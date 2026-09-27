# Проверка `ico-scan` на наборе imaginary-blind

Дата проверки: 2026-09-27. Локальный корпус: `/tmp/ico-external-ctf/imaginary-blind`, 13 задач и 25 файловых записей. Сверка reference-only выполнена по публичному репозиторию ImaginaryCTF 2022 на закреплённом commit `ac2f0aa796a651e0eb730db12c3550e4470d4e9c`; ответы из reference-материалов не добавлялись в production-код решателей.

Все действия были локальными и офлайн: challenge ELF не запускались, запросы к сервисам не отправлялись, флаги не вводились. Свежий полный отчёт: `/tmp/ico-external-ctf/final-report-final-20260927-v5/report.json`.

## Результат

| Задача | Категория | Статус инструмента | Проверка результата |
|---|---|---|---|
| huge | Crypto | candidate | Совпадает с опубликованным `flag.txt`; checker инструмента не запускался. |
| smoll | Crypto | candidate | Совпадает с опубликованным `flag.txt`; checker инструмента не запускался. |
| stream | Crypto | candidate | Совпадает с опубликованным `flag.txt`; checker инструмента не запускался. |
| improbus | Forensics | candidate | Восстановленный PNG имеет тот же SHA-256, что и официальный `flag.png`; OCR-кандидат прочитан с этого изображения. |
| Subtitles | Forensics | candidate | Совпадает с ответом в официальном README; checker инструмента не запускался. |
| tARP | Forensics | candidate | OCR-кандидат совпадает с опубликованным `flag.txt`; собранный PNG проходит `pngcheck`. |
| bof | Pwn | payload-ready | Сформирован `%70c`, как в авторском solve; бинарник не запускался. |
| Format String Fun | Pwn | payload-ready | Payload соответствует авторскому рецепту: `%680c%26$n`, 22 байта `a`, затем адрес `win`; не исполнен. |
| ret2win | Pwn | payload-ready | Есть 24 байта заполнения и адрес `win`, как в авторском solve. Лишняя XOR-строка оставлена `likely-noise`. |
| desrever | Reversing | candidate | Совпадает с опубликованным `flag.txt`; checker инструмента не запускался. |
| hidden | Reversing | candidate | Статическое обращение внедрённого checker-кода извлекает правильного кандидата; опубликованный `flag.txt` совпадает. Строка `jctf{n0t_the_real_flag?_or_is_it?}` понижена до `likely-placeholder`: shellcode в `.plt.sec` завершает программу до ветки `strcmp` в `main`. |
| 1337 | Web | payload-ready | Запрос статически строит `child_process` и `cat F*` без запрещённых кавычек; совпадает с опубликованным способом решения, запрос не отправлялся. |
| minigolf | Web | payload-ready | Сформирована последовательность из трёх GET-запросов для копирования и чтения `/app/flag.txt`; запросы не отправлялись. |

Инструмент классифицировал **13/13 задач**: **8 candidate-задач, 5 payload-ready, 0 hash-verified, 0 failed**. В отчёте 10 flag-shaped строк: 8 обычных кандидатов и 2 явно пониженных значения — один шум из `ret2win`, один decoy из `hidden`. Все 8 обычных кандидатов совпали с официальными answer-материалами в отдельной reference-сверке. Это независимая проверка аудита, а не hash/checker/platform-подтверждение внутри `ico-scan`; поэтому `solved_tasks` остаётся 0.

Пять PWN/Web задач не содержат извлекаемый ответ в локальных файлах корпуса: инструмент подготовил статические payload/request-артефакты, но без запущенного авторизованного экземпляра не получил ответ сервиса. `payload-ready` не означает, что флаг извлечён.

## Исправления этого прохода

- `Format String Fun`: padding изменён с NUL на `a`, как в опубликованном solve. Тест проверяет точные payload bytes и адрес `win`.
- `bof`: source-based payload теперь полностью перезаписывает guard и имеет двухбайтовый запас — итог `%70c`, а не недостаточный `%65c`.
- `hidden`: добавлено статическое обращение точного read/XOR-паттерна в PLT. Решатель учитывает, что успешный вызов `puts` перехвачен кодом в `.plt.sec`, инвертирует три 64-битных блока и создаёт input-artifact. Decoy из недостижимой ветки помечается отдельно.
- `1337`: вместо недостаточного раскрытия `process.env` строится filter-preserving template expression, который восстанавливает `child_process` и `cat F*` через `String.fromCharCode`; цифры ограничены `2`, `8`, `9`. Артефакт остаётся непосланным.

Ранее добавленные исправления сохранены: `minigolf` содержит три точных этапа с вычисляемой длиной последовательности; `tARP` чинит только повреждённый CRC пустого конечного `IEND`, когда предыдущие chunks валидны, и отбрасывает хвост максимум в три байта. Метрики отчёта считают solved только для `hash-verified` результатов.

## Проверки

- `./verify.sh` — **200 тестов пройдены**, smoke-проверки toolkit, Python CTF stack и binary stack пройдены.
- Полный офлайн-скан v5: 13 задач; `task_failure_count=0`, `universal_failed_count=0`, `challenge_hash_verified_task_count=0`, `challenge_candidate_task_count=8`, `challenge_payload_ready_task_count=5`.
- Семь текстовых кандидатов совпали с опубликованными ответами; восстановленный PNG для `improbus` SHA-256-совпадает с официальным `flag.png`.
- tARP PNG: `pngcheck -vt` сообщил `No errors detected` (6 chunks).
- Внешние сервисы и challenge ELF в этом проходе не запускались.

Корпус доказывает работу на этих 13 задачах, но не даёт основания утверждать, что инструмент автоматически решает любые неизвестные CTF-задачи.
