import asyncio
from playwright.async_api import async_playwright

async def capture_screenshot(target_url, full_page=False):
    if not target_url:
        raise ValueError('URL is missing')

    if not (target_url.startswith('http://') or target_url.startswith('https://')):
        target_url = 'http://' + target_url

    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True, args=['--no-sandbox'])
            context = await browser.new_context()
            page = await context.new_page()
            await page.goto(target_url, wait_until='domcontentloaded')

            # Set a timeout for page loading
            await page.wait_for_timeout(8000)
            await page.wait_for_selector('body')

            screenshot = await page.screenshot(full_page=full_page)
            await browser.close()

            return screenshot
    except Exception as e:
        raise ValueError(f'Error capturing screenshot: {str(e)}')

# # Example usage
async def main():
    target_url = 'https://www.cricbuzz.com'  # Replace with the URL you want to capture
    try:
        screenshot = await capture_screenshot(target_url, full_page=True)
        with open('screenshot.png', 'wb') as file:
            file.write(screenshot)
        print("Screenshot saved as 'screenshot.png'")
    except ValueError as e:
        print(f"Error: {e}")

if __name__ == '__main__':
    asyncio.run(main())
