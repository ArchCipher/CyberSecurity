#!/usr/bin/env python3

"""
./spider [-rlp] URL

-r : recursively downloads the images in a URL received as a parameter.
-r -l [N] :indicates the maximum depth level of the recursive download.
If not indicated, it will be 5.
-p [PATH] : indicates the path where the downloaded files will be saved.
If not specified, ./data/ will be used.

1. fetch page
2. parse for <a href> or <img src>
3. resolve relative urls, download images

NOTE:
  robots.txt is not read
  noindex meta tag or header in the HTTP response is not respected
"""

import argparse
import hashlib
from concurrent.futures import ThreadPoolExecutor, as_completed
import sys
from shutil import copyfileobj
import http.client
from urllib.request import Request, urlopen
import urllib.error
from urllib.parse import urlsplit, urljoin, urldefrag
from collections import deque, defaultdict
from pathlib import Path
from bs4 import BeautifulSoup

EXTENSIONS = (".jpg", ".jpeg", ".png", ".gif", ".bmp")
DEFAULT_DEPTH = 5
DEFAULT_DIR = "./data/"
MAX_WORKERS = 8


class ArachnidaError(Exception):
    pass


class Crawler:
    @staticmethod
    def fetch(url: str, timeout: float = 10) -> tuple[str, bytes]:
        """return body along with final_url (i.e., redirected links if any)"""
        req = Request(url, headers={"User-Agent": "spider/1.0"})
        try:
            with urlopen(req, timeout=timeout) as f:
                return f.geturl(), f.read()
        except (
            http.client.HTTPException,
            OSError,
            urllib.error.HTTPError,
            urllib.error.URLError,
        ) as e:
            raise ArachnidaError(f"{url}: {e}") from e


class ImageDownloader:
    """Download images to target_dir/file"""

    @staticmethod
    def download(
        executor: ThreadPoolExecutor,
        urls: list[str],
        dest_dir: str,
        timeout: float = 10,
    ) -> None:
        if not urls:
            return
        futures = [
            executor.submit(ImageDownloader._get_img, url, dest_dir, timeout)
            for url in urls
        ]
        for future in as_completed(futures):
            try:
                future.result()
            except ArachnidaError as e:
                print(f"download error: {e}", file=sys.stderr)
                continue

    @staticmethod
    def _image_name(url: str) -> str:
        p = Path(urlsplit(url).path)
        stem = p.stem or "image"
        # [:8] collisions are negligible for 100s of images.
        # for ~10k ~1% collisions, maybe this would need [:12] or larger
        return (
            f"{stem}_{hashlib.sha256(url.encode()).hexdigest()[:8]}{p.suffix.lower()}"
        )

    @staticmethod
    def _get_img(url: str, dest_dir: str, timeout: float = 10) -> Path:
        dest = Path(dest_dir) / ImageDownloader._image_name(url)
        if dest.exists():
            return dest
        req = Request(url, headers={"User-Agent": "spider/1.0"})
        # create tmp so partial files do not survive
        tmp = dest.with_name(dest.name + ".part")
        try:
            dest.parent.mkdir(parents=True, exist_ok=True)
            with urlopen(req, timeout=timeout) as f, open(tmp, "wb") as out:
                copyfileobj(f, out)
            tmp.replace(dest)
        except (
            http.client.HTTPException,
            OSError,
            urllib.error.HTTPError,
            urllib.error.URLError,
        ) as e:
            tmp.unlink(missing_ok=True)  # unlink partial files
            raise ArachnidaError(f"{url}: {e}") from e
        print(f"img {url}")
        return dest


def parse_args(argv=None) -> argparse.Namespace:
    """
    ./spider [-rlp] URL
    -r: recursively downloads the images in a URL.
    -r -l N: maximum depth level of the recursive download; default is 5.
    -p PATH: path where the downloaded files will be saved; default is ./data/.
    """
    parser = argparse.ArgumentParser(prog="spider")
    parser.add_argument("-r", action="store_true", help="recursively download images")
    parser.add_argument(
        "-l",
        type=int,
        metavar="N",
        help=f"maximum recursion depth (default {DEFAULT_DEPTH}, requires -r)",
    )
    parser.add_argument(
        "-p",
        default=DEFAULT_DIR,
        metavar="PATH",
        help=f"directory where images are saved (default {DEFAULT_DIR})",
    )
    parser.add_argument("url", metavar="URL", help="starting URL")
    args = parser.parse_args(argv)
    # strip whitespace
    args.url = args.url.strip()
    o = urlsplit(args.url)
    # https://user:pw@example.com:8443/a?b#c where,
    # scheme='https' netloc='user:pw@example.com:8443'
    # hostname='example.com' port=8443 path='a' query='b' fragment='c'
    if o.scheme not in ("http", "https") or not o.netloc:
        parser.error(f"Invalid URL {args.url}")
    if args.l is not None and not args.r:
        parser.error("-l requires -r")
    if args.l is not None and args.l < 0:
        parser.error("-l must be >= 0")
    return args


def is_image(url: str) -> bool:
    return urlsplit(url).path.lower().endswith(EXTENSIONS)


def extract_img_urls(soup, base_url: str):
    for img in soup.find_all("img"):
        src = img.get("src")
        if src:
            yield urljoin(base_url, src)


def extract_page_urls(soup, base_url: str):
    for a in soup.find_all("a"):
        href = a.get("href")
        if href:
            yield urljoin(base_url, urldefrag(href).url)


def main(argv=None) -> None:
    args = parse_args(argv)
    # remove fragment
    start_url = urldefrag(args.url).url
    origin_host = None
    max_depth = args.l if args.l is not None else DEFAULT_DEPTH
    queue = deque([(start_url, 0)])  # deque of url, depth
    seen_pages = {start_url}
    page_count: dict[int, int] = defaultdict(int)
    seen_images = set()
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        while queue:
            page_url, depth = queue.popleft()
            page_count[depth] += 1
            if page_count[depth] % 10 == 0:
                print(f"depth={depth} page={page_count[depth]} {page_url}")
            try:
                final_url, body = Crawler.fetch(page_url)
            except ArachnidaError as exc:
                print(f"error: {exc}", file=sys.stderr)
                continue
            if origin_host is None:
                origin_host = urlsplit(final_url).hostname
            seen_pages.add(final_url)  # alias dedupe (best-effort)
            soup = BeautifulSoup(body, features="html.parser")
            # get the first <base href> in the file
            base_tag = soup.find("base", href=True)
            base_url = urljoin(final_url, base_tag["href"]) if base_tag else final_url
            urls = []
            for url in extract_img_urls(soup, base_url):
                if is_image(url) and url not in seen_images:
                    seen_images.add(url)
                    urls.append(url)
            ImageDownloader.download(executor, urls, args.p)
            if args.r and depth < max_depth:
                for url in extract_page_urls(soup, base_url):
                    if urlsplit(url).hostname != origin_host:
                        continue
                    if url not in seen_pages:
                        seen_pages.add(url)
                        queue.append((url, depth + 1))
    print("pages per depth:", dict(sorted(page_count.items())))


if __name__ == "__main__":
    main()
