# Synthetic ICO follow-up regression tasks

These are authorized local fixtures derived from the temporary benchmark. They preserve three cases that were not direct flag candidates in the first scanner run:

- `crypto_easy_caesar`: natural-language Caesar shift wording.
- `forensics_hard_dns-fragments`: Base32 split across DNS labels.
- `reverse_hard_ret2win-review`: static ret2win/format-string review; the expected evidence state is `payload-ready`, not a claimed flag.

The expected flag values are intentionally kept out of this fixture directory. Run the local scanner from the toolkit root:

```sh
./ico-scan benchmarks/ico_synthetic_unresolved --out ./ico-scan-runs/synthetic-unresolved
```

No network requests or binary execution are required.

The integration regression expects two local candidate values and one static
`payload-ready` result. The reverse case deliberately does not claim a flag;
its only expected result is an evidence-only payload built from the explicit
offset and target address in `task.txt`.
