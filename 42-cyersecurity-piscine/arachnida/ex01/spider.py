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
"""
