# <p align="center"> Arachnida - Web scraping and metadata </p>

## Description

### 42 Project | Cybersecurity - web scraping and metadata

### Objective
Create a small program to
- automatically extract information from the web.
- analyze these files and manipulate the metadata.

### Overview

Exercise 1 - Spider
	The spider program allow you to extract all the images from a website, recursively, by providing a url as a parameter.

	You have to manage the following program options:
	./spider [-rlp] URL
	• Option -r : recursively downloads the images in a URL received as a parameter.
	• Option -r -l [N] :indicates the maximum depth level of the recursive download. If not indicated, it will be 5.
	• Option -p [PATH] : indicates the path where the downloaded files will be saved. If not specified, ./data/ will be used.

	The program will download the following extensions by default:
	• .jpg/jpeg
	• .png
	• .gif
	• .bmp

Exercise 2 - Scorpion
	The second scorpion program receive image files as parameters and must be able to
	parse them for EXIF and other metadata, displaying them on the screen.
	The program must at least be compatible with the same extensions that spider handles.
	It display basic attributes such as the creation date, as well as EXIF data. The out-
	put format is up to you.
	./scorpion FILE1 [FILE2 ...]

---

## Instructions

### Requirements

- python3

Create a venv and `pip install` the modules required.

Modules:
- bs4 (BeautifulSoup)

### Run

```sh
# To run spider:
./ex01/spider [-rlp] URL

# To run scorpion:
./ex02/scropion FILE1 [FILE2 ...]
```

---

## EXIF (Exchangeable image file format)

EXIF metadata tags cover:
Camera settings
Image metrics: Pixel dimensions, resolution, colorspace, and filesize
Date and time info
Location
Thumbnail
Descriptions
Copyright info

NOTE:
Use `hexed.it` for browser version of hex dump or:
```sh
# hex dump
xxd -l 64 photo.jpg
```


## SEO Crawl Efficiency Hygiene
Crawl hygiene: Optimizing how search engines crawl your site so they focus on important, indexable pages instead of wasting requests on low‑value URLs.

Googlebot actively enforces a strict 2MB HTML fetch limit; it simply truncates any byte beyond this threshold, meaning it neither renders nor indexes that content.

Time to First Byte (TTFB) measures the exact duration between Googlebot initiating an HTTP request and receiving the first single byte of data from the origin server.

---

## Resources

[argparse — Parser for command-line options](https://docs.python.org/3/library/argparse.html)
[urllib.parse — Parse URLs into components](https://docs.python.org/3/library/urllib.parse.html)
[urllib.request — Extensible library for opening URLs](https://docs.python.org/3/library/urllib.request.html)
[Beautiful Soup Documentation](https://beautiful-soup-4.readthedocs.io/en/latest/)
[shutil — High-level file operations](https://docs.python.org/3/library/shutil.html)
[Magic bytes - list of file signatures](https://en.wikipedia.org/wiki/List_of_file_signatures)
[Exiftool tag list: JPEG](https://exiftool.org/TagNames/JPEG.html)
[Exiftool tag list: EXIF](https://exiftool.org/TagNames/EXIF.html)
[ExifRead 3.5.1](https://pypi.org/project/ExifRead/)
[hexed: view hex bytes](https://hexed.it/)
[Crawling infrastructure: Optimize your crawl budget](https://developers.google.com/crawling/docs/crawl-budget)
[Crawl Efficiency Hygiene](https://searchenginezine.com/technical/crawl-index/crawl-efficiency-hygiene/)
