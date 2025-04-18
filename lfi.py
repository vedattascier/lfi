#!/usr/bin/env python
import argparse
import asyncio
import csv
import json
import logging
import os
import signal
import sys
import time
from datetime import datetime
from typing import List, Tuple, Union

import aiofiles
import aiohttp
from colorama import init as colorama_init
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn

# Terminal renk desteği için Colorama başlatılıyor.
colorama_init(autoreset=True)
console = Console()

# Sade "LFi" ASCII art banner.
BANNER = r"""
░▒▓█▓▒░      ░▒▓████████▓▒░▒▓█▓▒░ 
░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░ 
░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░ 
░▒▓█▓▒░      ░▒▓██████▓▒░ ░▒▓█▓▒░ 
░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░ 
░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░ 
░▒▓████████▓▒░▒▓█▓▒░      ░▒▓█▓▒░ 

  Geliştirici: Vedat Taşçıer
"""

# Varsayılan arama kriterleri ve User-Agent seçenekleri.
DEFAULT_KEYWORDS = ["root:x", "[fonts]", "MZ"]
DEFAULT_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.1 Safari/605.1.15"
]

# Logger konfigürasyonu.
logger = logging.getLogger("LFI_Scanner")
logger.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
console_handler = logging.StreamHandler(sys.stdout)
console_handler.setLevel(logging.INFO)
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)


def setup_file_logger(output_dir: str, timestamp: str):
    """Dosya loglama ayarlarını yapar."""
    if not os.path.isdir(output_dir):
        os.makedirs(output_dir)
    file_log = os.path.join(output_dir, f"scanner_debug_{timestamp}.log")
    file_handler = logging.FileHandler(file_log)
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    logger.debug("Dosya loglama yapılandırıldı: %s", file_log)


def print_banner():
    console.print(BANNER, style="cyan bold")
    console.print("[bold magenta]Gelişmiş Asenkron LFI Tarama Aracına hoş geldiniz![/bold magenta]\n")

def parse_args() -> argparse.Namespace:
    """Komut satırı argümanlarını tanımlar ve çözümler."""
    parser = argparse.ArgumentParser(
        description="Gelişmiş asenkron LFI Scanner: URL parametresi, wordlist ve ek özelliklerle hedef taraması yapar."
    )
    parser.add_argument("-u", "--url", type=str,
                        help="Hedef site URL'si (parametreli). Örnek: http://example.com/page.php?file=", required=False)
    parser.add_argument("-w", "--wordlist", type=str,
                        help="Wordlist dosyasının adı. Örnek: lfi-wordlist.txt", required=False)
    parser.add_argument("-c", "--concurrency", type=int,
                        help="Eşzamanlı istek sayısı (default: 50)", default=50)
    parser.add_argument("-to", "--timeout", type=int,
                        help="HTTP istek zaman aşımı (saniye, default: 10)", default=10)
    parser.add_argument("-k", "--keywords", type=str, nargs='*',
                        help="Aranacak metinler (default: %(default)s)", default=DEFAULT_KEYWORDS)
    parser.add_argument("-ua", "--useragent", type=int,
                        help="Kullanılacak User-Agent numarası (default: 1, mevcut: 1-%(max)s)", default=1)
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Detaylı çıktı göster (verbose)")
    parser.add_argument("-o", "--output", type=str,
                        help="Sonuçların kaydedileceği dizin (default: mevcut klasör)", default=".")
    args = parser.parse_args()

    # User-Agent numarası kontrolü.
    if args.useragent < 1 or args.useragent > len(DEFAULT_USER_AGENTS):
        args.useragent = 1
    return args


def get_user_input(args: argparse.Namespace) -> argparse.Namespace:
    """
    Eksik argümanlar için kullanıcıdan etkileşimli veri alır.
    Eğer aynı dizinde 'wordlist.txt' varsa, otomatik olarak onu kullanır.
    """
    if not args.url:
        args.url = console.input("[yellow]🔗 Hedef site URL'si (parametreli): [/yellow]").strip()

    if not args.wordlist:
        default_wordlist = "wordlist.txt"
        if os.path.isfile(default_wordlist):
            args.wordlist = default_wordlist
            console.print(f"[green]✅ '{default_wordlist}' bulundu, otomatik olarak kullanılacak.[/green]")
        else:
            args.wordlist = console.input("[yellow]📄 Wordlist dosyasının adı: [/yellow]").strip()

    return args


async def load_wordlist(filename: str) -> List[str]:
    """
    Wordlist dosyasını asenkron şekilde yükler ve payload listesini döner.
    """
    try:
        async with aiofiles.open(filename, mode="r", encoding="utf-8") as f:
            content = await f.read()
        payloads = [line.strip() for line in content.splitlines() if line.strip()]
        console.print(f"\n[cyan]🔍 Toplam [bold]{len(payloads)}[/bold] payload taranıyor...[/cyan]\n")
        logger.debug("Wordlist '%s' başarıyla yüklendi; toplam payload: %d", filename, len(payloads))
        return payloads
    except FileNotFoundError:
        logger.error("Wordlist dosyası bulunamadı: %s", filename)
        console.print(f"[red] [!] Wordlist dosyası bulunamadı: {filename}[/red]")
        sys.exit(1)
    except Exception as e:
        logger.exception("Wordlist yüklenirken hata: %s", e)
        console.print(f"[red] [!] Wordlist yüklenirken hata: {e}[/red]")
        sys.exit(1)


def graceful_exit(signum, frame):
    """Kullanıcı sinyali alındığında temiz çıkış sağlar."""
    console.print("\n[magenta bold] [!] Kullanıcı tarafından işlemin kesildi. Çıkılıyor...[/magenta bold]")
    logger.info("Tarama kullanıcı tarafından iptal edildi (signal: %s)", signum)
    sys.exit(1)


# SIGINT ve SIGTERM sinyallerinde temiz çıkış için.
signal.signal(signal.SIGINT, graceful_exit)
signal.signal(signal.SIGTERM, graceful_exit)


async def scan_payload(
    session: aiohttp.ClientSession,
    base_url: str,
    payload: str,
    keywords: List[str],
    timeout: int,
    semaphore: asyncio.Semaphore,
    verbose: bool = False
) -> Tuple[Union[bool, None], str, Union[int, None], Union[int, str]]:
    """
    Verilen payload için HTTP isteği gerçekleştirir ve HTTP 200 dönerse 'açık' kabul eder.
    """
    test_url = base_url + payload
    async with semaphore:
        try:
            async with session.get(test_url, timeout=timeout) as response:
                text = await response.text()
                if response.status == 200:
                    if verbose:
                        console.print(f"[green bold][+] Açık: {test_url}[/green bold] | HTTP: {response.status} | Boyut: {len(text)}")
                    logger.debug("Pozitif hit (HTTP 200): %s, Boyut: %d", test_url, len(text))
                    return True, test_url, response.status, len(text)
                else:
                    if verbose:
                        console.print(f"[red][-] Denendi (HTTP {response.status}): {test_url}[/red]")
                    logger.debug("HTTP kodu 200 değil: %s (kod: %s)", test_url, response.status)
                    return False, test_url, response.status, len(text)
        except Exception as e:
            if verbose:
                console.print(f"[magenta][!] Hata: {test_url} -> {e}[/magenta]")
            logger.exception("İstek sırasında hata oluştu (%s): %s", test_url, e)
            return None, test_url, None, str(e)


async def write_logs(found_entries: List[dict], output_dir: str, timestamp: str):
    """
    Sonuçları TXT, JSON ve CSV formatlarında log dosyalarına yazar.
    """
    if not os.path.isdir(output_dir):
        os.makedirs(output_dir)
    log_txt = os.path.join(output_dir, f"bulunan_aciklar_{timestamp}.txt")
    log_json = os.path.join(output_dir, f"bulunan_aciklar_{timestamp}.json")
    log_csv = os.path.join(output_dir, f"bulunan_aciklar_{timestamp}.csv")
    try:
        # TXT log.
        async with aiofiles.open(log_txt, "w", encoding="utf-8") as f_txt:
            await f_txt.write("URL | HTTP Kodu | İçerik Boyutu\n")
            for entry in found_entries:
                await f_txt.write(f"{entry['url']} | {entry['http_code']} | {entry['content_length']}\n")
        # JSON log.
        async with aiofiles.open(log_json, "w", encoding="utf-8") as f_json:
            await f_json.write(json.dumps(found_entries, indent=4))
        # CSV log.
        async with aiofiles.open(log_csv, "w", encoding="utf-8", newline="") as f_csv:
            await f_csv.write("URL,HTTP Kodu,İçerik Boyutu\n")
            for entry in found_entries:
                await f_csv.write(f"{entry['url']},{entry['http_code']},{entry['content_length']}\n")
        console.print(f"\n[green bold]🎯 Toplam {len(found_entries)} açık bulundu![/green bold]")
        console.print(f"[cyan]Sonuçlar:[/cyan] [bold]{log_txt}[/bold] | [bold]{log_json}[/bold] | [bold]{log_csv}[/bold]")
        logger.info("Log dosyaları başarıyla yazıldı: %s, %s, %s", log_txt, log_json, log_csv)
    except Exception as e:
        logger.exception("Log dosyaları yazılırken hata oluştu: %s", e)
        console.print(f"[red] [!] Log dosyaları yazılamadı: {e}[/red]")


def display_results_table(results: List[Tuple[Union[bool, None], str, Union[int, None], Union[int, str]]]):
    """
    Tarama sonuçlarını terminalde tablo halinde gösterir.
    """
    table = Table(title="Tarama Sonuçları", style="bright_magenta")
    table.add_column("Durum", justify="center", style="bold")
    table.add_column("URL", justify="left")
    table.add_column("HTTP Kodu", justify="center")
    table.add_column("İçerik Boyutu", justify="center")
    for status, url, code, info in results:
        if status is True:
            status_text = "[green]Açık[/green]"
        elif status is False:
            status_text = "[red]Denendi[/red]"
        else:
            status_text = "[magenta]Hata[/magenta]"
        table.add_row(status_text, url, str(code) if code else "-", str(info))
    console.print(table)


async def main():
    print_banner()
    args = parse_args()
    args = get_user_input(args)

    start_time = time.time()
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    setup_file_logger(args.output, timestamp)

    payloads = await load_wordlist(args.wordlist)
    results: List[Tuple[Union[bool, None], str, Union[int, None], Union[int, str]]] = []
    found_entries: List[dict] = []

    chosen_ua = DEFAULT_USER_AGENTS[args.useragent - 1]
    console.print(f"[cyan bold]⚙️ Kullanılan User-Agent:[/cyan bold] {chosen_ua}")
    console.print(f"[cyan bold]⚙️ Eşzamanlı istek sayısı:[/cyan bold] {args.concurrency} | [cyan bold]Zaman aşımı:[/cyan bold] {args.timeout}s")
    console.print(f"[cyan bold]⚙️ Aranan kriter:[/cyan bold] {args.keywords}\n")

    timeout_setting = aiohttp.ClientTimeout(total=args.timeout)
    async with aiohttp.ClientSession(timeout=timeout_setting, headers={"User-Agent": chosen_ua}) as session:
        semaphore = asyncio.Semaphore(args.concurrency)
        tasks = [
            scan_payload(session, args.url, payload, args.keywords, args.timeout,
                         semaphore, args.verbose)
            for payload in payloads
        ]

        with Progress(
            SpinnerColumn(),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.1f}%"),
            transient=True
        ) as progress:
            task_progress = progress.add_task("[yellow]Payload taranıyor...", total=len(tasks))
            for coro in asyncio.as_completed(tasks):
                result = await coro
                results.append(result)
                if result[0] is True:
                    found_entries.append({
                        "url": result[1],
                        "http_code": result[2],
                        "content_length": result[3]
                    })
                progress.advance(task_progress)

    display_results_table(results)
    await write_logs(found_entries, args.output, timestamp)

    elapsed = time.time() - start_time
    console.print(f"\n[cyan bold]⏱️ Tarama tamamlandı.[/cyan bold] Toplam süre: [bold]{round(elapsed, 2)}[/bold] saniye. [cyan]({len(payloads)} payload denendi)[/cyan]\n")
    logger.info("Tarama tamamlandı: %d saniye, %d payload denendi.", round(elapsed, 2), len(payloads))


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except Exception as e:
        logger.exception("Fatal error: %s", e)
        console.print(f"[red]Fatal error: {e}[/red]")
