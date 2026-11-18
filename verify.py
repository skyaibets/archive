#!/usr/bin/env python3
"""Проверка архива Sky AI Bets на вашем компьютере, без нашего сайта.

    python3 verify.py           проверить весь архив и показать, что проверено по каждой записи
    python3 verify.py --demo    показать, как ловится подделка: в памяти меняется коэффициент одной ставки
                                (файл на диске не трогается), и видно, где цепочка рвётся

Как это работает. Каждая запись в ledger.jsonl хранит свой «отпечаток» (hash) — SHA-256 от её содержимого — и
отпечаток предыдущей записи (prev_hash). Скрипт сам заново считает отпечаток каждой записи и сравнивает:
  1) совпадает ли посчитанный отпечаток с записанным — значит, запись не меняли;
  2) совпадает ли prev_hash с отпечатком предыдущей записи — значит, между ними ничего не удаляли и не вставляли.
Подписи бота проверяются, если установлен пакет pynacl (pip install pynacl).
"""

import base64
import copy
import hashlib
import json
import sys
from pathlib import Path

HERE = Path(__file__).parent
STAGE = {"draft": "после драфта", "min10": "10-я минута", "min15": "15-я минута"}


def canonical(r: dict) -> str:
    return json.dumps({k: v for k, v in r.items() if k not in ("hash", "sig")},
                      sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def describe(r: dict, maps: dict) -> str:
    t = r["type"]
    if t == "MAP":
        return f"карта: {r['radiant']} — {r['dire']}" + (f", карта {r['game_no']}" if r.get("game_no") else "")
    if t == "DECISION":
        m = maps.get(r["map"], {})
        where = f"{m.get('radiant', '?')} — {m.get('dire', '?')}, {STAGE.get(r['stage'], r['stage'])}"
        if r["action"] == "BET":
            side = "больше" if r["side"] == "over" else "меньше"
            return f"ставка №{r['bet_no']}: {where}, {side} {r['line']}, кэф {r['odds']}, {r['stake']} ₽"
        return f"пропуск: {where}"
    if t == "POST":
        return f"пост №{r['post_id']} в канале к записи {r['of_seq']}"
    if t == "RECHECK":
        return f"проверка линии через {r['waited_s']} с после ставки №{r['bet_no']}"
    if t == "SETTLE":
        return f"итог карты: {r['total_kills']} убийств"
    return t


def check(records: list[dict], key, verbose: bool = True) -> int | None:
    """Returns the number of the first record that fails, or None."""
    maps = {}
    prev = "GENESIS"
    for i, r in enumerate(records, 1):
        if r["type"] == "MAP":
            maps[r["map"]] = r
        h = hashlib.sha256(canonical(r).encode("utf-8")).hexdigest()
        same = h == r["hash"]
        linked = r["prev_hash"] == prev and r["seq"] == i
        signed = None
        if key is not None:
            try:
                key.verify(r["hash"].encode(), base64.b64decode(r["sig"]))
                signed = True
            except Exception:
                signed = False
        ok = same and linked and signed is not False
        if verbose or not ok:
            print(f"{'✅' if ok else '❌'} запись {i}: {describe(r, maps)}")
            print(f"     отпечаток посчитан сейчас: {h[:16]}…  записан в архиве: {r['hash'][:16]}…"
                  f"  → {'совпадает' if same else 'НЕ СОВПАДАЕТ — запись изменена'}")
            print(f"     ссылка на предыдущую запись: {r['prev_hash'][:16]}…"
                  f"  → {'совпадает' if linked else 'НЕ СОВПАДАЕТ — между записями что-то удалено, вставлено или изменено'}")
            if signed is not None:
                print(f"     подпись бота: {'верна' if signed else 'НЕ ВЕРНА'}")
        if not ok:
            return i
        prev = r["hash"]
    return None


def main() -> int:
    records = [json.loads(l) for l in (HERE / "ledger.jsonl").read_text(encoding="utf-8").splitlines() if l.strip()]
    try:
        from nacl.signing import VerifyKey
        key = VerifyKey(base64.b64decode((HERE / "pubkey.txt").read_text().strip()))
    except ImportError:
        key = None
    if "--demo" in sys.argv:
        bets = [r for r in records if r["type"] == "DECISION" and r.get("action") == "BET"]
        if not bets:
            print("В архиве пока нет ставок для демонстрации.")
            return 0
        fake = copy.deepcopy(records)
        victim = next(r for r in fake if r["seq"] == bets[0]["seq"])
        old = victim["odds"]
        victim["odds"] = round(old + 0.5, 2)
        print(f"Демонстрация: меняем в памяти коэффициент ставки №{victim['bet_no']} с {old} на {victim['odds']}.\n")
        bad = check(fake, key, verbose=False)
        print(f"\nПодделка найдена в записи {bad}: её содержимое больше не даёт записанный отпечаток."
              "\nА если пересчитать и сам отпечаток, порвётся ссылка в следующей записи — и так до конца архива."
              "\nФайл ledger.jsonl на диске не изменён.")
        return 0
    bad = check(records, key)
    print()
    if bad:
        print(f"❌ Архив не прошёл проверку на записи {bad}.")
        return 1
    print(f"✅ Проверено записей: {len(records)}. Скрипт сам пересчитал каждую на вашем компьютере: ни одна не изменена, ничего не удалено.")
    if key is None:
        print("   Подписи бота не проверялись: установите pynacl (pip install pynacl) и запустите снова.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
