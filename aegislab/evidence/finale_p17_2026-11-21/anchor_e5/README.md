# Base mainnet anchor proof (copied from finale P16 part E5, 20 Nov 2026)

- `bundle/`: the released evidence bundle of playground run TRY-006-G (Prompt B, guard mode both), exported by the console,
  with `anchor.json` (the Base receipt): tx `0xb1d568e2bef36402bb8d43ab43b0b4253d93a402f16fbef0fc3ac65b3095daf5`,
  block 60073297, fee 154301393444 wei, posted 0.07 min after the terminal checkpoint.
- `tampered/`: the same bundle with 2 audit lines deleted.
- `check_good.json`: `python -m aegis.anchor check --bundle bundle --address 0xDbba805310adB5b20e1418EA6C690f7698638483` → exit 0.
- `check_tampered.json`: the same check on `tampered/` → exit 1 (the audit log no longer matches the anchored terminal checkpoint).

Files are byte-identical copies of the P16 run; nothing was re-signed. Re-run the check (read-only RPC, no transaction):

    python -m aegis.anchor check --bundle evidence/finale_p17_2026-11-21/anchor_e5/bundle --address 0xDbba805310adB5b20e1418EA6C690f7698638483
