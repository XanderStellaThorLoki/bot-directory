```python
#!/usr/bin/env python3
import sys
import asyncio
import logging
import csv
import os
import urllib.parse
import random
import time
import ssl
import json
from playwright.async_api import async_playwright, TimeoutError as PlaywrightTimeoutError
from bs4 import BeautifulSoup
from selenium import webdriver
from selenium.webdriver.firefox.service import Service as FirefoxService
from selenium.webdriver.firefox.options import Options as FirefoxOptions
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, WebDriverException, NoSuchElementException
from fake_useragent import UserAgent
from selenium_stealth import stealth
import psutil
import tempfile
import shutil
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
import base64
import hashlib
import time as time_module
import os as os_module
import urllib.parse as url_parse

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s [%(levelname)s] %(message)s')
logging.debug("Script started")
# ID: L1

def cleanup_browser_processes():
    try:
        logging.debug("Cleaning up browser processes")
        firefox_count = 0
        geckodriver_count = 0
        for proc in psutil.process_iter(['name', 'pid']):
            try:
                if proc.name().lower() in ['firefox.exe', 'geckodriver.exe']:
                    logging.debug(f"Terminating process: {proc.name()} (PID: {proc.pid})")
                    proc.kill()
                    if proc.name().lower() == 'firefox.exe':
                        firefox_count += 1
                    else:
                        geckodriver_count += 1
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                logging.debug(f"Skipping inaccessible process: {proc.name()} (PID: {proc.pid})")
                continue
        logging.info(f"Cleaned up {firefox_count} Firefox and {geckodriver_count} GeckoDriver processes")
        return firefox_count + geckodriver_count
    except Exception as e:
        logging.warning(f"Error cleaning up processes: {e}")
        return 0
# ID: L26

async def scroll_page(method, page=None, driver=None):
    try:
        logging.debug("Scrolling page to load dynamic content")
        if method == "playwright" and page:
            last_height = await page.evaluate("document.body.scrollHeight")
            retries = 5
            for _ in range(retries):
                await page.evaluate("window.scrollBy(0, document.body.scrollHeight)")
                await asyncio.sleep(3.0)
                new_height = await page.evaluate("document.body.scrollHeight")
                if new_height == last_height:
                    break
                last_height = new_height
        elif method == "selenium" and driver:
            last_height = driver.execute_script("return document.body.scrollHeight")
            retries = 5
            for _ in range(retries):
                driver.execute_script("window.scrollBy(0, document.body.scrollHeight)")
                time.sleep(3.0)
                new_height = driver.execute_script("return document.body.scrollHeight")
                if new_height == last_height:
                    break
                last_height = new_height
        logging.debug("Page scrolled successfully")
    except Exception as e:
        logging.debug(f"Failed to scroll page: {e}")
# ID: L49

async def wait_for_video_elements(method, page=None, driver=None, timeout=60000):
    try:
        if method == "playwright" and page:
            await page.wait_for_selector("video, iframe, embed, source", timeout=timeout)
        elif method == "selenium" and driver:
            WebDriverWait(driver, timeout / 1000).until(EC.presence_of_element_located((By.CSS_SELECTOR, "video, iframe, embed, source")))
    except Exception as e:
        logging.debug(f"Failed to wait for video elements: {e}")
# ID: L58

async def handle_popup(page):
    try:
        async with page.expect_popup() as popup_info:
            popup = await popup_info.value
            logging.debug(f"Pop-up detected: {popup.url}")
            await popup.click("button:has-text('Akzeptieren')", timeout=5000)
            logging.debug("Accepted pop-up")
    except Exception as e:
        logging.debug(f"Failed to handle pop-up: {e}")
# ID: L66

def handle_selenium_popup(driver):
    try:
        WebDriverWait(driver, 5).until(EC.alert_is_present())
        alert = driver.switch_to.alert
        alert.accept()
        logging.debug("Accepted Selenium pop-up")
    except Exception:
        pass
# ID: L74

async def get_video_properties(method, page=None, driver=None, soup_element=None, max_retries=3):
    try:
        logging.debug("Extracting video properties")
        sticky = False
        autoplay = soup_element.get('autoplay', False) is not False
        muted = soup_element.get('muted', False) is not False
        controls = soup_element.get('controls', False) is not False
        width = 0
        height = 0

        for attempt in range(max_retries):
            try:
                if method == "playwright" and page:
                    element = await page.query_selector(f"css=[src='{soup_element.get('src')}']") or await page.query_selector(f"css=[data-src='{soup_element.get('src')}']")
                    if element:
                        position = await page.evaluate("el => window.getComputedStyle(el).position", element)
                        sticky = position in ['fixed', 'sticky']
                        width = await page.evaluate("el => el.clientWidth", element)
                        height = await page.evaluate("el => el.clientHeight", element)
                        if width > 0 or height > 0:
                            break
                        await asyncio.sleep(1.0 * (attempt + 1))
                elif method == "selenium" and driver:
                    xpath = f"//*[(@src='{soup_element.get('src')}' or @data-src='{soup_element.get('src')}') and (self::video or self::iframe or self::embed or self::source)]"
                    element = driver.find_element(By.XPATH, xpath)
                    if element:
                        position = driver.execute_script("return window.getComputedStyle(arguments[0]).position", element)
                        sticky = position in ['fixed', 'sticky']
                        width = driver.execute_script("return arguments[0].clientWidth", element)
                        height = driver.execute_script("return arguments[0].clientHeight", element)
                        if width > 0 or height > 0:
                            break
                        time.sleep(1.0 * (attempt + 1))
            except NoSuchElementException:
                break
            except Exception as e:
                logging.debug(f"Attempt {attempt + 1} failed: {e}")
                if attempt < max_retries - 1:
                    await asyncio.sleep(1.0 * (attempt + 1))
                continue

        ad_elements = soup_element.find_all(['iframe', 'div'], class_=lambda x: x and any(kw in x.lower() for kw in ['ads', 'sponsor', 'advert']))
        content_elements = soup_element.find_all(['video', 'source'])
        ad_count = len(ad_elements)
        content_count = len(content_elements) or 1
        ad_content_ratio = ad_count / (ad_count + content_count) if (ad_count + content_count) > 0 else 0.0

        logging.debug(f"Video properties: Sticky={sticky}, Autoplay={autoplay}, Muted={muted}, Controls={controls}, Width={width}, Height={height}, Ad_Content_Ratio={ad_content_ratio}")
        return {
            'sticky': sticky,
            'autoplay': autoplay,
            'muted': muted,
            'controls': controls,
            'width': width,
            'height': height,
            'ad_content_ratio': ad_content_ratio
        }
    except Exception as e:
        logging.debug(f"Failed to extract video properties: {e}")
        return {
            'sticky': False,
            'autoplay': False,
            'muted': False,
            'controls': False,
            'width': 0,
            'height': 0,
            'ad_content_ratio': 0.0
        }
# ID: L123

async def describe_link(link_text, target_url):
    try:
        logging.debug(f"Describing link: Text={link_text}, URL={target_url}")
        link_text = link_text.strip()[:100] if link_text else "No text"
        if not link_text or link_text == "No text":
            return "Unnamed video link"
        if any(kw in target_url.lower() for kw in ['youtube.com', 'vimeo.com', 'video', 'watch', 'play', 'media', 'stream', 'clip', 'vid']):
            return f"Link to video about {link_text.lower()}"
        return f"Link to page about {link_text.lower()}"
    except Exception as e:
        logging.debug(f"Error describing link: {e}")
        return "Unnamed link"
# ID: L136

def check_price_override(url, price):
    override_file = r"C:\Users\mjbao\Desktop\Vidium\Final Scraper\scraper_app\price_overrides.json"
    try:
        if os.path.exists(override_file):
            with open(override_file, 'r', encoding='utf-8') as f:
                overrides = json.load(f)
        else:
            overrides = {}
        key = f"{url}:{price}"
        return overrides.get(key, False)
    except Exception as e:
        logging.error(f"Error checking price override for {url}: {e}")
        return False
# ID: L147

def log_price_override_request(url, price):
    override_file = r"C:\Users\mjbao\Desktop\Vidium\Final Scraper\scraper_app\price_overrides.json"
    try:
        overrides = {}
        if os.path.exists(override_file):
            with open(override_file, 'r', encoding='utf-8') as f:
                overrides = json.load(f)
        key = f"{url}:{price}"
        if key not in overrides:
            logging.warning(f"Price {price} USD exceeds max for {url}. Approve override in {override_file} by setting '{key}': true")
            overrides[key] = False
            with open(override_file, 'w', encoding='utf-8') as f:
                json.dump(overrides, f, indent=2)
    except Exception as e:
        logging.error(f"Error logging price override for {url}: {e}")
# ID: L160

async def crawl_url(url, base_dir, run_name, run_count, consolidated_file, use_playwright=True):
    link_data = []
    browser = None
    driver = None
    profile_dir = None
    run_data = {
        'run_count': run_count,
        'thread_id': "single_thread",
        'urls_processed': [],
        'video_data': [],
        'errors': [],
        'pages_visited': 0
    }
    try:
        # Normalize URL to ensure it has a protocol
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        logging.debug(f"Starting crawl for URL: {url} with {('Playwright' if use_playwright else 'Selenium')}")

        # Bright Data Proxy Configuration (Using Proxy Manager port 22225)
        proxy = 'http://brd-customer-hl_a4e0f011-zone-residential_proxy1-country-us:mj6q9jjm47bo@localhost:22225'
        ssl_context = ssl._create_unverified_context()

        if use_playwright:
            try:
                playwright = await async_playwright().start()
                browser = await playwright.firefox.launch(headless=False)
                context = await browser.new_context(
                    user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
                    proxy={"server": proxy},
                    ignore_https_errors=True
                )
                # ID: L167
                # Load private key
                with open(r'C:\Users\mjbao\Desktop\Vidium\Final Scraper\scraper_app\private-key.pem', 'rb') as f:
                    private_key_pem = f.read()
                # ID: L169
                private_key = serialization.load_pem_private_key(private_key_pem, password=None)
                # ID: L170

                # Compute JWK and thumbprint
                public_key = private_key.public_key()
                # ID: L172
                public_numbers = public_key.public_numbers()
                # ID: L173
                n = base64.urlsafe_b64encode(public_numbers.n.to_bytes((public_numbers.n.bit_length() + 7) // 8, byteorder='big')).decode('utf-8').rstrip('=')
                # ID: L174
                e = base64.urlsafe_b64encode(public_numbers.e.to_bytes((public_numbers.e.bit_length() + 7) // 8, byteorder='big')).decode('utf-8').rstrip('=')
                # ID: L175
                jwk = {"kty": "RSA", "n": n, "e": e}
                # ID: L176
                jwk_json = json.dumps(jwk, sort_keys=True, separators=(',', ':'))
                # ID: L177
                thumbprint = base64.urlsafe_b64encode(
                    hashlib.sha256(jwk_json.encode('utf-8')).digest()
                ).decode('utf-8').rstrip('=')
                # ID: L180

                # Signature agent URL
                signature_agent_url = 'https://bot-directory.rubiconcaesar.workers.dev/.well-known/http-message-signatures-directory'
                # ID: L182

                async def get_signed_headers(request_url):
                    authority = url_parse.urlparse(request_url).netloc
                    created = int(time_module.time())
                    expires = created + 300  # 5 minutes
                    nonce = base64.urlsafe_b64encode(os_module.urandom(32)).decode('utf-8').rstrip('=')
                    components = '("@authority" "signature-agent")'
                    params = f';created={created};expires={expires};keyid="{thumbprint}";nonce="{nonce}";alg="rsa-sha256";tag="web-bot-auth"'
                    sig_input = f'sig={components}{params}'
                    base = f'"@authority": {authority}\n"signature-agent": "{signature_agent_url}"\n"@signature-params": {components}{params}'
                    sig_bytes = private_key.sign(
                        base.encode('utf-8'),
                        padding.PKCS1v15(),
                        hashes.SHA256()
                    )
                    sig = base64.urlsafe_b64encode(sig_bytes).decode('utf-8').rstrip('=')
                    return {
                        'Signature-Agent': f'"{signature_agent_url}"',
                        'Signature-Input': sig_input,
                        'Signature': f'sig=:{sig}:'
                    }
                # ID: L198

                # Max price willing to pay per crawl (in USD; ~0.01374 CAD)
                max_crawl_price = 0.01
                # ID: L200

                async def sign_and_pay_handler(route):
                    headers = dict(route.request.headers)
                    signed_headers = await get_signed_headers(route.request.url)
                    headers.update(signed_headers)
                    response = await route.fetch(headers=headers)
                    if response.status == 402:
                        price_header = response.headers.get('crawler-price')
                        if price_header:
                            price = float(price_header)
                            if price <= max_crawl_price:
                                pay_headers = {'crawler-max-price': str(max_crawl_price)}
                                headers.update(pay_headers)
                                response = await route.fetch(headers=headers)
                                if response.status == 200:
                                    charged = response.headers.get('crawler-charged', '0')
                                    logging.debug(f"Paid {charged} USD for {route.request.url}")
                                else:
                                    logging.error(f"Payment failed for {route.request.url}")
                            else:
                                if check_price_override(route.request.url, price):
                                    pay_headers = {'crawler-max-price': str(price)}
                                    headers.update(pay_headers)
                                    response = await route.fetch(headers=headers)
                                    if response.status == 200:
                                        charged = response.headers.get('crawler-charged', '0')
                                        logging.debug(f"Paid {charged} USD (override) for {route.request.url}")
                                    else:
                                        logging.error(f"Override payment failed for {route.request.url}")
                                else:
                                    log_price_override_request(route.request.url, price)
                                    logging.error(f"Price {price} USD exceeds max {max_crawl_price} USD for {route.request.url}")
                    await route.fulfill(response=response)
                # ID: L224

                page = await context.new_page()
                # ID: L225
                await page.route("**/*", sign_and_pay_handler)
                # ID: L226
                page.on("popup", lambda popup: asyncio.create_task(handle_popup(popup)))
                # ID: L227
                await page.goto(url, wait_until="networkidle", timeout=180000)
                run_data['urls_processed'].append({'url': url, 'success': True, 'loaded': url, 'proxy': True})
                await page.wait_for_load_state("networkidle")
                await scroll_page("playwright", page=page)
                await wait_for_video_elements("playwright", page=page, timeout=60000)
            except PlaywrightTimeoutError as e:
                logging.error(f"Playwright timeout for {url}: {e}")
                run_data['errors'].append(f"Timeout error for {url}: {e}")
                await browser.close() if browser else None
                await playwright.stop() if playwright else None
            except Exception as e:
                logging.error(f"Playwright error for {url}: {e}")
                run_data['errors'].append(f"Error for {url}: {e}")
                await browser.close() if browser else None
                await playwright.stop() if playwright else None
        else:
            try:
                cleanup_browser_processes()
                geckodriver_path = r"C:\Users\mjbao\Desktop\Vidium\Final Scraper\geckodriver.exe"
                firefox_binary_path = r"C:\Program Files\Mozilla Firefox\firefox.exe"
                if not os.path.exists(geckodriver_path):
                    logging.error(f"GeckoDriver not found at: {geckodriver_path}")
                    return link_data, run_data
                if not os.path.exists(firefox_binary_path):
                    logging.error(f"Firefox not found at: {firefox_binary_path}")
                    return link_data, run_data

                ua = UserAgent()
                service = FirefoxService(geckodriver_path)
                options = FirefoxOptions()
                options.binary_location = firefox_binary_path
                options.set_preference("network.proxy.type", 1)
                options.set_preference("network.proxy.http", "localhost")
                options.set_preference("network.proxy.http_port", 22225)
                options.set_preference("network.proxy.ssl", "localhost")
                options.set_preference("network.proxy.ssl_port", 22225)
                options.set_preference("network.proxy.no_proxies_on", "")
                options.set_preference("general.useragent.override", ua.random)
                options.set_preference("dom.webdriver.enabled", False)
                options.set_preference("javascript.enabled", True)
                options.set_preference("security.enterprise_roots.enabled", True)
                driver = webdriver.Firefox(service=service, options=options)
                driver.get(url)
                handle_selenium_popup(driver)
                WebDriverWait(driver, 180).until(EC.presence_of_element_located((By.TAG_NAME, "body")))
                run_data['urls_processed'].append({'url': url, 'success': True, 'loaded': url, 'proxy': True})
                scroll_page("selenium", driver=driver)
                wait_for_video_elements("selenium", driver=driver, timeout=60000)
            except (TimeoutException, WebDriverException) as e:
                logging.error(f"Selenium error for {url}: {e}")
                run_data['errors'].append(f"Error for {url}: {e}")
                if driver:
                    driver.quit()
                return link_data, run_data
            except Exception as e:
                logging.error(f"General Selenium error for {url}: {e}")
                run_data['errors'].append(f"Error for {url}: {e}")
                if driver:
                    driver.quit()
                return link_data, run_data

        if use_playwright and page:
            content = await page.content()
            soup = BeautifulSoup(content, 'html.parser')
        elif driver:
            soup = BeautifulSoup(driver.page_source, 'html.parser')
        else:
            return link_data, run_data

        logging.debug(f"Parsed page source for {url}, length: {len(str(soup))}")
        video_elements = soup.find_all(['video', 'iframe', 'embed', 'source'])
        video_links = soup.find_all('a', href=lambda href: href and any(kw in href.lower() for kw in ['youtube.com', 'vimeo.com', 'video', 'watch', 'play', 'media', 'stream', 'clip', 'vid']))

        for element in video_elements:
            src = element.get('src') or element.get('data-src')
            if src and src.startswith(('http://', 'https://')):
                normalized_src = src if src.startswith(('http://', 'https://')) else urllib.parse.urljoin(url, src)
                properties = await get_video_properties("playwright" if use_playwright else "selenium", page=page, driver=driver, soup_element=element)
                description = await describe_link(element.get('title', '') or element.get('alt', '') or 'Video', normalized_src)
                video_entry = {
                    'source_url': url,
                    'target_url': normalized_src,
                    'link_text': "Video Element",
                    'description': description,
                    'domain': urllib.parse.urlparse(url).netloc,
                    'sticky': properties['sticky'],
                    'autoplay': properties['autoplay'],
                    'muted': properties['muted'],
                    'controls': properties['controls'],
                    'width': properties['width'],
                    'height': properties['height'],
                    'ad_content_ratio': properties['ad_content_ratio']
                }
                link_data.append(list(video_entry.values()))
                run_data['video_data'].append(video_entry)
                logging.debug(f"Logged video element: {normalized_src}")

        for link in video_links[:10]:
            href = link.get('href')
            if href and href.startswith(('http://', 'https://')):
                normalized_href = href if href.startswith(('http://', 'https://')) else urllib.parse.urljoin(url, href)
                link_text = link.get_text(strip=True) or link.get('title', '') or 'Video Link'
                description = await describe_link(link_text, normalized_href)
                properties = await get_video_properties("playwright" if use_playwright else "selenium", page=page, driver=driver, soup_element=link)
                video_entry = {
                    'source_url': url,
                    'target_url': normalized_href,
                    'link_text': link_text[:100],
                    'description': description,
                    'domain': urllib.parse.urlparse(url).netloc,
                    'sticky': properties['sticky'],
                    'autoplay': properties['autoplay'],
                    'muted': properties['muted'],
                    'controls': properties['controls'],
                    'width': properties['width'],
                    'height': properties['height'],
                    'ad_content_ratio': properties['ad_content_ratio']
                }
                link_data.append(list(video_entry.values()))
                run_data['video_data'].append(video_entry)
                logging.debug(f"Logged video link: {normalized_href}")

        # Crawl subpages (up to 5000 pages, 10 links per page)
        links = soup.find_all('a', href=True)
        visited_urls = {url}
        urls_to_visit = set()
        for a in links[:10]:
            href = a.get('href')
            if href and not href.startswith('#') and href.startswith(('http://', 'https://')):
                normalized_url = href if href.startswith(('http://', 'https://')) else urllib.parse.urljoin(url, href)
                if normalized_url and urllib.parse.urlparse(normalized_url).netloc == urllib.parse.urlparse(url).netloc and normalized_url not in visited_urls:
                    urls_to_visit.add(normalized_url)

        while urls_to_visit and len(visited_urls) < 5000:
            current_url = urls_to_visit.pop()
            if current_url in visited_urls:
                continue
            try:
                if use_playwright and page:
                    await page.goto(current_url, wait_until="networkidle", timeout=180000)
                    run_data['urls_processed'].append({'url': current_url, 'success': True, 'loaded': current_url, 'proxy': True})
                    await page.wait_for_load_state("networkidle")
                    await scroll_page("playwright", page=page)
                    await wait_for_video_elements("playwright", page=page, timeout=60000)
                    content = await page.content()
                elif driver:
                    driver.get(current_url)
                    handle_selenium_popup(driver)
                    WebDriverWait(driver, 180).until(EC.presence_of_element_located((By.TAG_NAME, "body")))
                    run_data['urls_processed'].append({'url': current_url, 'success': True, 'loaded': current_url, 'proxy': True})
                    scroll_page("selenium", driver=driver)
                    wait_for_video_elements("selenium", driver=driver, timeout=60000)
                    content = driver.page_source
                else:
                    continue

                soup = BeautifulSoup(content, 'html.parser')
                video_elements = soup.find_all(['video', 'iframe', 'embed', 'source'])
                video_links = soup.find_all('a', href=lambda href: href and any(kw in href.lower() for kw in ['youtube.com', 'vimeo.com', 'video', 'watch', 'play', 'media', 'stream', 'clip', 'vid']))

                for element in video_elements:
                    src = element.get('src') or element.get('data-src')
                    if src and src.startswith(('http://', 'https://')):
                        normalized_src = src if src.startswith(('http://', 'https://')) else urllib.parse.urljoin(current_url, src)
                        properties = await get_video_properties("playwright" if use_playwright else "selenium", page=page, driver=driver, soup_element=element)
                        description = await describe_link(element.get('title', '') or element.get('alt', '') or 'Video', normalized_src)
                        video_entry = {
                            'source_url': current_url,
                            'target_url': normalized_src,
                            'link_text': "Video Element",
                            'description': description,
                            'domain': urllib.parse.urlparse(current_url).netloc,
                            'sticky': properties['sticky'],
                            'autoplay': properties['autoplay'],
                            'muted': properties['muted'],
                            'controls': properties['controls'],
                            'width': properties['width'],
                            'height': properties['height'],
                            'ad_content_ratio': properties['ad_content_ratio']
                        }
                        link_data.append(list(video_entry.values()))
                        run_data['video_data'].append(video_entry)
                        logging.debug(f"Logged video element: {normalized_src}")

                for link in video_links[:10]:
                    href = link.get('href')
                    if href and href.startswith(('http://', 'https://')):
                        normalized_href = href if href.startswith(('http://', 'https://')) else urllib.parse.urljoin(current_url, href)
                        link_text = link.get_text(strip=True) or link.get('title', '') or 'Video Link'
                        description = await describe_link(link_text, normalized_href)
                        properties = await get_video_properties("playwright" if use_playwright else "selenium", page=page, driver=driver, soup_element=link)
                        video_entry = {
                            'source_url': current_url,
                            'target_url': normalized_href,
                            'link_text': link_text[:100],
                            'description': description,
                            'domain': urllib.parse.urlparse(current_url).netloc,
                            'sticky': properties['sticky'],
                            'autoplay': properties['autoplay'],
                            'muted': properties['muted'],
                            'controls': properties['controls'],
                            'width': properties['width'],
                            'height': properties['height'],
                            'ad_content_ratio': properties['ad_content_ratio']
                        }
                        link_data.append(list(video_entry.values()))
                        run_data['video_data'].append(video_entry)
                        logging.debug(f"Logged video link: {normalized_href}")

                for a in soup.find_all('a', href=True)[:10]:
                    href = a.get('href')
                    if href and not href.startswith('#') and href.startswith(('http://', 'https://')):
                        normalized_url = href if href.startswith(('http://', 'https://')) else urllib.parse.urljoin(current_url, href)
                        if normalized_url and urllib.parse.urlparse(normalized_url).netloc == urllib.parse.urlparse(current_url).netloc and normalized_url not in visited_urls:
                            urls_to_visit.add(normalized_url)
                visited_urls.add(current_url)
            except PlaywrightTimeoutError as e:
                run_data['errors'].append(f"Timeout error for {current_url}: {e}")
                logging.error(f"Timeout error for {current_url}: {e}")
            except Exception as e:
                run_data['errors'].append(f"Error processing {current_url}: {e}")
                logging.error(f"Error processing {current_url}: {e}")

        run_data['pages_visited'] = len(visited_urls)
        with open(os.path.join(base_dir, "scraper_logs", run_name, f"run_{run_count}_video_network.csv"), 'a', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            for row in link_data:
                writer.writerow(row)
            logging.debug(f"Wrote {len(link_data)} links to CSV")

    except Exception as e:
        run_data['errors'].append(f"Error crawling {url}: {e}")
        logging.error(f"Error crawling {url}: {e}")

    finally:
        if use_playwright and browser:
            await browser.close()
            await playwright.stop() if 'playwright' in locals() else None
        elif driver:
            try:
                driver.quit()
                logging.debug("Driver quit successfully")
            except Exception as e:
                run_data['errors'].append(f"Error quitting driver: {e}")
                logging.error(f"Error quitting driver: {e}")
        if profile_dir and os.path.exists(profile_dir):
            shutil.rmtree(profile_dir, ignore_errors=True)
        try:
            with open(consolidated_file, 'a', encoding='utf-8') as f:
                json.dump(run_data, f, indent=2)
                f.write('\n')
        except Exception as e:
            logging.error(f"Failed to write to consolidated file: {e}")

    return link_data, run_data
# ID: L350

def main():
    try:
        logging.debug("Entering main function")
        logging.debug(f"Arguments: {sys.argv}")
        if len(sys.argv) != 3 or sys.argv[2].lower() != 'csv':
            logging.error("Invalid arguments. Usage: python crawl_network.py <RunName> CSV")
            print("Usage: python crawl_network.py <RunName> CSV")
            sys.exit(1)

        run_name = sys.argv[1]
        logging.debug(f"Main: RunName={run_name}")
        
        run_count_file = r"C:\Users\mjbao\Desktop\Vidium\Final Scraper\scraper_app\run_count.txt"
        run_count = 0
        if os.path.exists(run_count_file):
            with open(run_count_file, 'r') as f:
                run_count = int(f.read().strip())
        run_count += 1
        with open(run_count_file, 'w') as f:
            f.write(str(run_count))
        
        base_dir = r"C:\Users\mjbao\Desktop\Vidium\Final Scraper\scraper_app"
        os.makedirs(os.path.join(base_dir, "scraper_logs", run_name), exist_ok=True)
        
        csv_file = os.path.join(base_dir, 'Crawler Site list 1 (Premium) - Sheet1.csv')
        if not os.path.exists(csv_file):
            logging.error(f"CSV file not found: {csv_file}")
            sys.exit(1)
        with open(csv_file, 'r', encoding='utf-8') as f:
            reader = csv.reader(f)
            next(reader, None)  # Skip header if present
            for row in reader:
                if not row or not row[0].strip():
                    continue
                url = row[0].strip()
                logging.debug(f"Processing URL from CSV: {url}")
                asyncio.run(crawl_url(url, base_dir, run_name, run_count, os.path.join(base_dir, "scraper_runs.json")))

    except Exception as e:
        logging.error(f"Error in main: {e}")
        sys.exit(1)
# ID: L387

if __name__ == "__main__":
    main()
# ID: L389
```
