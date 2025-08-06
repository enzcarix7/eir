from socket import gethostbyname, gethostbyaddr, herror
from concurrent.futures import ThreadPoolExecutor, as_completed
from os import makedirs, listdir
from os.path import isfile, exists, join
from signal import signal, SIGINT
from sys import stdout
from threading import Lock, Thread
from urllib.parse import urlparse
from warnings import filterwarnings
from requests import get, head, RequestException, Response
from time import sleep
from random import choice
from datetime import datetime
from Wappalyzer import Wappalyzer, WebPage

time_now = lambda: datetime.now().strftime('%H:%M:%S')

# Global vars
request_count: int = 0
request_lock = Lock()
print_lock = Lock()
count_200: int = 0
count_403: int = 0
count_others: int = 0
stop_flag: bool = False
executor = None


def check_technologies(url: str):
    wappalyzer = Wappalyzer.latest()
    safe_print("\033[96m[TECHNOLOGIES CHECK] Finding technologies\033[0m")
    try:
        webpage = WebPage.new_from_url(url)
        technologies = wappalyzer.analyze(webpage)
        if technologies:
            safe_print("\033[96m[TECHNOLOGIES CHECK] Technologies found:\033[0m")
            for tech in technologies:
                safe_print(f"\033[96m\t- {tech}\033[0m")
            print("\n")
        else:
            safe_print("\033[96m[TECHNOLOGIES CHECK] No technologies found.\033[0m")
    except Exception as wappalyzer_error:
        safe_print(f"\033[31m[ERROR Wappalyzer] {wappalyzer_error}\033[0m")
        pass


def sigint_handler(_signum, _frame):
    global stop_flag, executor
    if not stop_flag:
        print('\n\033[31m[!] Ctrl+C pressed, stopping gracefully...\033[0m')
        stop_flag = True

    else:
        print('\n\033[31m[!] Force exit...\033[0m')
        exit(1)


def safe_print(msg):
    with print_lock:
        stdout.write('\r\033[K')
        stdout.write(msg + '\n')
        stdout.flush()


def draw_progress_bar(progress):
    with print_lock:
        stdout.write('\r\033[K')
        stdout.write(progress)
        stdout.flush()


def handle_429_retry(base_url, word, tag_dir, tag_file, delay, retry_count=0, max_retries=3):
    if retry_count >= max_retries:
        safe_print(f'\033[31m[ {time_now()} ] Max retries reached for {word}, skipping...\033[0m')
        return False
    safe_print(
        f'\033[32m[ {time_now()} | HTTP 429 ] (Suggest: Switch ur IP) Sleeping 30 secs, retry {retry_count + 1}/{max_retries}\033[0m')
    sleep(30)
    return fuzz_single_url(base_url, word, tag_dir, tag_file, delay, retry_count + 1, max_retries)


def check_url(url: str) -> tuple[bool, str | None]:
    schemes: list[str] = ["http://", "https://"]
    for scheme in schemes:
        url_full = url if url.startswith(("http://", "https://")) else scheme + url
        try:
            parsed = urlparse(url_full)
            host = parsed.hostname
            ip = gethostbyname(host)
            try:
                rdns = gethostbyaddr(ip)[0]
            except herror:
                rdns = "N/A"

            print(
                f"\n\033[36m[URL CHECK] Scheme: {scheme.strip('://')} | Host: {host} | IP: {ip} | RDNS: {rdns}\033[0m")
            print(f"\033[36m[URL CHECK] Full URL: {url_full}\033[0m")

            resp = head(url_full, timeout=5, allow_redirects=True)
            if resp.history:
                print("\033[35m[URL CHECK] Redirection chain:\033[0m")
                previous_url = url_full
                for r in resp.history:
                    location = r.headers.get('Location')
                    print(f"\033[35m\t{r.status_code} | From: {previous_url} -> To: {location}\033[0m")
                    previous_url = location
                print(f"\033[35m\tFinal URL: {resp.url}\033[0m")
            print(f"\033[34m[URL CHECK] Server Header: {resp.headers.get('Server', 'N/A')}\033[0m")
            print(f"\033[34m[URL CHECK] Content-Type: {resp.headers.get('Content-Type', 'N/A')}\033[0m")
            print(f"\033[34m[URL CHECK] Content-Length: {resp.headers.get('Content-Length', 'N/A')}\033[0m")
            if resp.status_code == 200:
                print(f"\033[32m[URL CHECK] HTTP Status: 200 (reachable)\033[0m\n")
                check_technologies(url_full)
                return True, resp.url
            else:
                print(f"\033[33m[URL CHECK] HTTP Status: {resp.status_code} (skipping)\033[0m\n")
        except RequestException as url_request_error:
            print(f"\033[31m[!] Connection failed: {url_request_error}\033[0m\n")
        except Exception as url_exception_error:
            print(f"\033[31m[!] Unexpected error: {url_exception_error}\033[0m\n")
    return False, None


def fuzz_single_url(base_url: str, word: str, tag_dir: str, tag_file: str, delay: float, retry_count=0,
                    max_retries=3) -> None:
    global stop_flag, request_count, count_200, count_403, count_others
    if stop_flag:
        return
    user_agents: list[str] = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.5938.149 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:117.0) Gecko/20100101 Firefox/117.0",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.6045.200 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_5_2) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Safari/605.1.15",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/117.0.2045.60 Safari/537.36",
        "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:115.0) Gecko/20100101 Firefox/115.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_0_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.5845.97 Safari/537.36",
        "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Opera/102.0.4880.40 Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chromium/118.0.5993.89 Chrome/118.0.5993.89 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15"
    ]
    new_url = f"{base_url.rstrip('/')}/{word.lstrip('/')}"
    try:
        response: Response = get(new_url, headers={'User-Agent': choice(user_agents)})
        with request_lock:
            request_count += 1
        if response.status_code == 200:
            count_200 += 1
            safe_print(f"\033[92m[ {time_now()} | HTTP {response.status_code} ]     {new_url} \033[0m")
            with open(f'{tag_dir}/{tag_file}_200_fuzz.txt', 'a') as dir_200:
                dir_200.write(f"{new_url:<100}Content-Length: {len(response.text)}\n")
        elif response.status_code == 403:
            count_403 += 1
            safe_print(f"\033[33m[ {time_now()} | HTTP {response.status_code} ]     {new_url} \033[0m")
            with open(f'{tag_dir}/{tag_file}_403_fuzz.txt', 'a') as dir_403:
                dir_403.write(f"{new_url:<100}Content-Length: {len(response.text)}\n")
        elif response.status_code == 429:
            count_others += 1
            if not handle_429_retry(base_url, word, tag_dir, tag_file, delay, retry_count, max_retries):
                return
        else:
            count_others += 1
            safe_print(f"\033[31m[ {time_now()} | HTTP {response.status_code} ]     {new_url}\033[0m")
        sleep(delay)
    except Exception as fuzz_single_exception:
        safe_print(
            f"\033[31m[ {time_now()} ] ERROR URL: {new_url} - Error: {str(fuzz_single_exception)}\033[0m")


def progress_bar_watcher(total):
    global request_count, count_200, count_403, count_others
    while request_count < total:
        with request_lock:
            percent = request_count / total
            filled = int(30 * percent)
            bar = '█' * filled + '-' * (30 - filled)
            stdout.write(f'\r\033[96m[Progress] |{bar}| {int(percent * 100)}% '
                         f'| ({request_count}/{total}) - [URLs Finded] 200: {count_200} | 403: {count_403} | Others: {count_others}\033[0m')
            stdout.flush()
        sleep(0.2)
    stdout.write(f'\r\033[96m[Progress] |{"█" * 30}| 100% ({request_count}/{total}) -'
                 f'[URLs Finded] 200: {count_200} | 403: {count_403} | Others: {count_others}\033[0m\n')
    stdout.flush()


def fuzzer(url: str, words: list[str], delay: float, tag_dir: str, tag_file: str, max_threads: int) -> None:
    global executor
    print(f'\n[!] Starting fuzzing on {url} with {len(words)} items\n')
    progress_thread = Thread(target=progress_bar_watcher, args=(len(words),), daemon=True)
    progress_thread.start()
    executor = ThreadPoolExecutor(max_workers=max_threads)
    futures = [executor.submit(fuzz_single_url, url, word, tag_dir, tag_file, delay, 0, 3) for word in words]
    try:
        for future in as_completed(futures):
            if stop_flag:
                break
            future.result()
    except Exception as fuzzer_exception:
        print(f"[Error] {fuzzer_exception}")
    finally:
        executor.shutdown(wait=False)
        print("\n[!] Fuzzer stopped, exiting cleanly.")


if __name__ == '__main__':
    signal(SIGINT, sigint_handler)
    banner: str = (r"""
    ++++++++++++++++++++++++++
    fuzzing tool beta rev. 1.4
    ++++++++++++++++++++++++++
    """)
    print(banner)

    filterwarnings("ignore", category=UserWarning, module="Wappalyzer")

    try:
        # URL check
        while True:
            url_input = input("Enter the URL to fuzz: ").strip()
            valid, full_url = check_url(url_input)
            if valid:
                url_input = full_url
                break
            else:
                print("Please enter a valid and reachable URL (with HTTP 200).\n")

        # Wordlist check e load
        while True:
            wordlist_input: str = input("Enter the path to the wordlist file: ")
            if isfile(wordlist_input):
                with open(wordlist_input) as f:
                    wordlist = f.read().splitlines()
                break
            else:
                print(f"\033[31m[!] Wordlist not found at: {wordlist_input}. Try again.\033[0m")

        # Delay check
        while True:
            delay_input = input("Enter the delay between requests (default: 1s): ").strip()
            try:
                delay_input = float(delay_input or 1)
                if delay_input == 1:
                    print("Delay set to 1 second.")
                elif delay_input < 0:
                    print("Delay must be a positive number.")
                    continue
                break
            except ValueError:
                print("Please enter a valid number.")

        # Tag directory check
        tag_dir_input = input("Enter the path to the directory for output files (default: ./output): ").strip()
        if not tag_dir_input:
            print("Setting default output directory to ./output")
            tag_dir_input = "./output"
        if not exists(tag_dir_input):
            print(f"Directory '{tag_dir_input}' does not exist. Creating it...\n")
            makedirs(tag_dir_input, exist_ok=True)
        else:
            print("Directory already exist - OK")
        print(f"\nFiles in directory {tag_dir_input}:")
        files = [f for f in listdir(tag_dir_input) if isfile(join(tag_dir_input, f))]
        if files:
            for f in files:
                print("  -", f)
            print()
        else:
            print("  No files found in directory {tag_dir_input}\n")

        # Tag file check
        tag_file_input = input("Enter the output file name (default: 'fuzz'): ").strip()
        if not tag_file_input:
            print("Setting default output file name to 'fuzz'")
            tag_file_input = "fuzz"

        # Threads param
        max_threads_input = input("Enter number of threads (default: 10, max: 50): ").strip()
        try:
            max_threads_input = int(max_threads_input) if max_threads_input else 10
            if max_threads_input < 1:
                print("Threads count must be at least 1, setting to 10")
                max_threads_input = 10
            max_threads_input = min(max_threads_input, 50)
        except ValueError:
            print("Invalid threads number, setting to 10")
            max_threads_input = 10

        fuzzer(url_input, wordlist, delay_input, tag_dir_input, tag_file_input, max_threads_input)

    except Exception as e:
        print(f'[Error] {str(e)}')
