"""Authentication module - browser-based SSO login and session management."""

import base64
import secrets
import webbrowser
from urllib.parse import parse_qs, urlencode, urlparse

from .api import api, ProtonAPIError

# Proton OAuth configuration
AUTHORIZE_URL = "https://account.proton.me/authorize"


def generate_state() -> str:
    """Generate a random state for OAuth."""
    random_bytes = secrets.token_bytes(32)
    return base64.urlsafe_b64encode(random_bytes).decode().rstrip("=")


def get_login_url(state: str) -> str:
    """Generate the login URL for browser authentication."""
    params = {
        "app": "proton-vpn-browser-extension",
        "appVersion": "browser-vpn@1.2.13",
        "state": state,
        "t": "1",  # Login type
        "plan": "vpn2024",
    }
    return f"{AUTHORIZE_URL}?{urlencode(params)}"


def consume_fork(selector: str) -> dict:
    """Consume the session fork to get tokens."""
    return api.get(f"auth/sessions/forks/{selector}", include_auth=False)


def parse_selector_input(user_input: str) -> str:
    """
    Parse selector from user input.
    
    Accepts:
    - Just the selector: "wy2cqeobgx7p5ao2v3dinm4ha7tvgie5"
    - JSON format: {"Code":1000,"Selector":"xxx"}
    - selector=xxx format
    - Full URL with selector parameter
    """
    import json
    import re
    
    user_input = user_input.strip()
    
    # Try JSON format
    if user_input.startswith("{"):
        try:
            data = json.loads(user_input)
            if "Selector" in data:
                return data["Selector"]
        except json.JSONDecodeError:
            pass
    
    # Try selector=xxx format
    match = re.search(r'selector[=:]?\s*([a-zA-Z0-9]+)', user_input, re.IGNORECASE)
    if match:
        return match.group(1)
    
    # Try URL with selector parameter
    if "://" in user_input:
        parsed = urlparse(user_input)
        for params_str in [parsed.fragment, parsed.query]:
            if params_str:
                params = parse_qs(params_str)
                if "selector" in params:
                    return params["selector"][0]
    
    # Assume it's the raw selector (alphanumeric string)
    if re.match(r'^[a-zA-Z0-9]+$', user_input) and len(user_input) > 10:
        return user_input
    
    raise ValueError("无法识别的输入格式")


def login_interactive() -> bool:
    """
    Perform interactive browser-based login.

    Opens browser for user to login, asks user to paste the selector,
    then exchanges fork selector for session tokens.

    Returns True on success.
    """
    state = generate_state()
    login_url = get_login_url(state)

    print("\n🔐 Proton VPN 登录流程")
    print("=" * 50)
    print("\n1. 正在打开浏览器，请登录您的 Proton 账户...")
    print(f"\n   如果浏览器没有自动打开，请手动访问：\n   {login_url}")
    
    # Open browser
    webbrowser.open(login_url)

    print("\n2. 登录成功后，打开 F12 开发者工具 -> Network 标签")
    print("   找到 'forks' 请求，复制响应中的 Selector 值")
    print("   或直接复制整个 JSON 响应")
    print("\n3. 将 Selector 粘贴到下面：")
    print("-" * 50)
    
    try:
        user_input = input("\n请粘贴 Selector: ").strip()
    except (KeyboardInterrupt, EOFError):
        print("\n❌ 登录已取消")
        return False
    
    if not user_input:
        print("❌ 未输入内容")
        return False
    
    # Parse the selector
    try:
        selector = parse_selector_input(user_input)
    except ValueError as e:
        print(f"❌ {e}")
        return False
    
    # Exchange selector for tokens
    try:
        result = consume_fork(selector)
        api.set_session(
            result["UID"],
            result["AccessToken"],
            result["RefreshToken"],
        )
        print("\n✅ 登录成功！")
        return True
    except ProtonAPIError as e:
        print(f"\n❌ 登录失败: {e}")
        return False


def logout() -> None:
    """Log out and clear session."""
    if api.is_logged_in():
        try:
            api.request("DELETE", "auth", retry_on_401=False)
        except ProtonAPIError:
            pass  # Ignore errors during logout
    api.clear_session()
    print("✅ 已退出登录")


def check_login() -> bool:
    """Check if currently logged in with valid session."""
    if not api.is_logged_in():
        return False

    try:
        # Verify session is still valid
        api.get("vpn/v1")
        return True
    except ProtonAPIError:
        return False
