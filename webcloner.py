import os
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin

def create_directory(path):
    if not os.path.exists(path):
        os.makedirs(path)

def save_html(url, path):
    response = requests.get(url)
    response.raise_for_status()

    with open(os.path.join(path, 'index.html'), 'w', encoding='utf-8') as file:
        file.write(response.text)

def save_images(soup, base_url, path):
    create_directory(os.path.join(path, 'images'))
    images = soup.find_all('img')
    for img in images:
        src = img.get('src')
        if not src:
            continue
        img_url = urljoin(base_url, src)
        try:
            img_data = requests.get(img_url).content
            img_name = os.path.basename(src.split('?')[0])  # remove query parameters
            with open(os.path.join(path, 'images', img_name), 'wb') as img_file:
                img_file.write(img_data)
        except requests.exceptions.RequestException as e:
            print(f"Failed to download image {img_url}: {e}")

def clone_website(url, path):
    create_directory(path)

    # Download HTML
    save_html(url, path)

    # Parse HTML
    with open(os.path.join(path, 'index.html'), 'r', encoding='utf-8') as file:
        soup = BeautifulSoup(file, 'html.parser')

    # Download images
    save_images(soup, url, path)

    print(f"Website cloned successfully to {path}")

def main():
    url = input("Enter the URL of the website to clone: ").strip()
    path = input("Enter the directory name to save the cloned website: ").strip()

    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url

    try:
        clone_website(url, path)
    except requests.exceptions.RequestException as e:
        print(f"An error occurred while accessing the website: {e}")

if __name__ == "__main__":
    main()
