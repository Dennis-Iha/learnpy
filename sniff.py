"""
Advanced Automated Network Interceptor & Web Automation Framework
With Self-Learning Loop for Accuracy Improvement
"""

import asyncio
import json
import logging
import time
from datetime import datetime
from typing import Dict, List, Any, Optional, Callable
import aiohttp
from aiohttp import ClientSession, ClientTimeout
from playwright.async_api import async_playwright, Page, Browser, Response, Route
from bs4 import BeautifulSoup
import numpy as np
from collections import deque
import pickle
import os
from dataclasses import dataclass, field
from enum import Enum

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('automation.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# ============ DATA STRUCTURES ============

@dataclass
class NetworkRequest:
    """Represents a network request"""
    url: str
    method: str
    headers: Dict[str, str]
    body: Optional[bytes]
    timestamp: float
    response_status: Optional[int] = None
    response_body: Optional[bytes] = None
    response_headers: Optional[Dict[str, str]] = None

@dataclass
class Action:
    """Represents a user action"""
    type: str  # click, fill, select, navigate, scroll, wait
    selector: Optional[str] = None
    value: Optional[Any] = None
    url: Optional[str] = None
    wait_time: Optional[float] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class ActionPrediction:
    """Predicted next action"""
    action: Action
    confidence: float
    alternatives: List[Action] = field(default_factory=list)

class PageState(Enum):
    """Page state detection"""
    LOGIN = "login"
    PRODUCT_LISTING = "product_listing"
    PRODUCT_DETAIL = "product_detail"
    CART = "cart"
    CHECKOUT = "checkout"
    SEARCH_RESULTS = "search_results"
    HOME = "home"
    UNKNOWN = "unknown"

# ============ NETWORK INTERCEPTOR ============

class NetworkInterceptor:
    """Intercepts HTTP/HTTPS and WebSocket traffic"""
    
    def __init__(self):
        self.requests: List[NetworkRequest] = []
        self.websockets: List[Dict] = []
        self.max_history = 10000
        
    async def start_interception(self, page: Page):
        """Set up interception on page"""
        # Intercept all responses
        page.on("response", self._on_response)
        page.on("request", self._on_request)
        page.on("websocket", self._on_websocket)
        
    def _on_request(self, request):
        """Handle outgoing request"""
        try:
            req = NetworkRequest(
                url=request.url,
                method=request.method,
                headers=request.headers,
                body=request.post_data_buffer if request.post_data else None,
                timestamp=time.time()
            )
            self.requests.append(req)
            self._trim_history()
            logger.debug(f"→ {request.method} {request.url}")
        except Exception as e:
            logger.error(f"Request interception error: {e}")
    
    def _on_response(self, response: Response):
        """Handle response"""
        try:
            for req in reversed(self.requests):
                if req.url == response.url and req.response_status is None:
                    req.response_status = response.status
                    req.response_headers = response.headers
                    break
            logger.debug(f"← {response.status} {response.url}")
        except Exception as e:
            logger.error(f"Response interception error: {e}")
    
    def _on_websocket(self, ws):
        """Handle WebSocket connections"""
        ws_data = {
            "url": ws.url,
            "frames_sent": [],
            "frames_received": [],
            "timestamp": time.time()
        }
        
        def on_sent(payload):
            ws_data["frames_sent"].append({
                "data": payload,
                "timestamp": time.time()
            })
        
        def on_received(payload):
            ws_data["frames_received"].append({
                "data": payload,
                "timestamp": time.time()
            })
        
        ws.on("framesent", on_sent)
        ws.on("framereceived", on_received)
        ws.on("close", lambda: logger.info(f"WebSocket closed: {ws.url}"))
        
        self.websockets.append(ws_data)
        logger.info(f"WebSocket connected: {ws.url}")
    
    def _trim_history(self):
        """Keep history bounded"""
        if len(self.requests) > self.max_history:
            self.requests = self.requests[-self.max_history:]
    
    def get_websocket_data(self) -> List[Dict]:
        return self.websockets
    
    def save_capture(self, filepath: str):
        """Save captured traffic"""
        data = {
            "requests": [
                {
                    "url": r.url,
                    "method": r.method,
                    "headers": r.headers,
                    "status": r.response_status,
                    "response_headers": r.response_headers,
                    "timestamp": r.timestamp
                } for r in self.requests
            ],
            "websockets": self.websockets
        }
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2, default=str)
        logger.info(f"Capture saved to {filepath}")

# ============ PAGE ANALYZER ============

class PageAnalyzer:
    """Analyzes page structure to predict actions"""
    
    COMMON_PATTERNS = {
        "login": {
            "urls": ["login", "signin", "auth", "account"],
            "selectors": [
                "input[type='email']",
                "input[type='password']",
                "input[name='username']",
                "button[type='submit']",
                "#login", ".login", "[data-testid='login']"
            ]
        },
        "product": {
            "urls": ["product", "item", "p/", "/dp/"],
            "selectors": [
                "[data-product-id]",
                ".product", ".product-card",
                "button.add-to-cart",
                "[class*='addToCart']",
                "[class*='add-to-cart']"
            ]
        },
        "cart": {
            "urls": ["cart", "basket", "checkout"],
            "selectors": [
                "[class*='cart']",
                "[class*='checkout']",
                "button[name='checkout']"
            ]
        },
        "search": {
            "urls": ["search", "results", "query"],
            "selectors": [
                "input[type='search']",
                "input[name='q']",
                "[role='searchbox']",
                "#search"
            ]
        }
    }
    
    @classmethod
    async def detect_page_state(cls, page: Page) -> PageState:
        """Detect current page state"""
        url = page.url.lower()
        content = await page.content()
        soup = BeautifulSoup(content, 'html.parser')
        
        # Check URL patterns
        for state, patterns in cls.COMMON_PATTERNS.items():
            for pattern in patterns["urls"]:
                if pattern in url:
                    return PageState(state)
        
        # Check for selectors
        for state, patterns in cls.COMMON_PATTERNS.items():
            for selector in patterns["selectors"]:
                if await page.query_selector(selector):
                    return PageState(state)
        
        return PageState.UNKNOWN
    
    @classmethod
    async def extract_interactive_elements(cls, page: Page) -> List[Dict]:
        """Extract all interactive elements from page"""
        return await page.evaluate("""
            () => {
                const elements = [];
                const selectors = 'a, button, input, select, textarea, [role="button"], [onclick]';
                
                document.querySelectorAll(selectors).forEach((el, idx) => {
                    const rect = el.getBoundingClientRect();
                    if (rect.width > 0 && rect.height > 0) {
                        elements.push({
                            tag: el.tagName.toLowerCase(),
                            type: el.type || null,
                            name: el.name || null,
                            id: el.id || null,
                            classes: Array.from(el.classList),
                            text: (el.innerText || el.value || el.placeholder || '').slice(0, 100),
                            href: el.href || null,
                            ariaLabel: el.getAttribute('aria-label'),
                            role: el.getAttribute('role'),
                            testId: el.getAttribute('data-testid'),
                            visible: rect.width > 0 && rect.height > 0,
                            index: idx
                        });
                    }
                });
                return elements;
            }
        """)
    
    @classmethod
    async def get_form_fields(cls, page: Page) -> List[Dict]:
        """Extract form fields with metadata"""
        return await page.evaluate("""
            () => {
                const fields = [];
                document.querySelectorAll('form').forEach((form, formIdx) => {
                    const formData = {
                        action: form.action,
                        method: form.method,
                        fields: []
                    };
                    form.querySelectorAll('input, select, textarea').forEach(field => {
                        formData.fields.push({
                            name: field.name,
                            type: field.type,
                            id: field.id,
                            placeholder: field.placeholder,
                            required: field.required,
                            value: field.type === 'password' ? '***' : field.value
                        });
                    });
                    fields.push(formData);
                });
                return fields;
            }
        """)

# ============ ACTION PREDICTOR ============

class ActionPredictor:
    """
    ML-based predictor for next best action.
    Uses a combination of heuristics + historical patterns.
    """
    
    def __init__(self, model_path: Optional[str] = None):
        self.model_path = model_path or "action_model.pkl"
        self.action_history: deque = deque(maxlen=1000)
        self.patterns: Dict[str, List[Action]] = {}
        self.success_rates: Dict[str, List[bool]] = {}
        self._load_model()
    
    def _load_model(self):
        """Load trained model if exists"""
        if os.path.exists(self.model_path):
            try:
                with open(self.model_path, 'rb') as f:
                    data = pickle.load(f)
                    self.patterns = data.get('patterns', {})
                    self.success_rates = data.get('success_rates', {})
                logger.info(f"Model loaded from {self.model_path}")
            except Exception as e:
                logger.warning(f"Could not load model: {e}")
    
    def save_model(self):
        """Persist learned patterns"""
        with open(self.model_path, 'wb') as f:
            pickle.dump({
                'patterns': self.patterns,
                'success_rates': self.success_rates
            }, f)
        logger.info(f"Model saved to {self.model_path}")
    
    def _state_key(self, page_state: PageState, elements: List[Dict]) -> str:
        """Create a hashable key for the current state"""
        element_signature = "|".join([
            f"{e['tag']}:{e.get('type') or ''}:{(e.get('text') or '')[:20]}"
            for e in elements[:15]
        ])
        return f"{page_state.value}::{hash(element_signature)}"
    
    async def predict_next_action(
        self,
        page: Page,
        goal: str = "navigate_and_interact",
        page_state: Optional[PageState] = None
    ) -> ActionPrediction:
        """
        Predict the next best action based on:
        1. Current page state
        2. Historical successful patterns
        3. Heuristic scoring
        """
        if page_state is None:
            page_state = await PageAnalyzer.detect_page_state(page)
        
        elements = await PageAnalyzer.extract_interactive_elements(page)
        
        if not elements:
            return ActionPrediction(
                action=Action(type="wait", wait_time=2.0),
                confidence=0.5
            )
        
        # Try historical pattern first
        state_key = self._state_key(page_state, elements)
        if state_key in self.patterns:
            historical = self.patterns[state_key]
            if historical:
                success = self.success_rates.get(state_key, [])
                if success:
                    rate = sum(success) / len(success)
                    if rate > 0.7:
                        return ActionPrediction(
                            action=historical[0],
                            confidence=min(rate, 0.95),
                            alternatives=historical[1:4]
                        )
        
        # Heuristic scoring for each element
        scored_actions = []
        for el in elements:
            score = self._score_element(el, page_state, goal)
            if score > 0:
                action = self._element_to_action(el)
                if action:
                    scored_actions.append((score, action))
        
        if not scored_actions:
            return ActionPrediction(
                action=Action(type="scroll", value=500),
                confidence=0.4
            )
        
        scored_actions.sort(key=lambda x: x[0], reverse=True)
        best_score, best_action = scored_actions[0]
        
        alternatives = [a for _, a in scored_actions[1:4]]
        
        return ActionPrediction(
            action=best_action,
            confidence=min(best_score / 100, 0.95),
            alternatives=alternatives
        )
    
    def _score_element(self, el: Dict, state: PageState, goal: str) -> float:
        """Score an element for actionability"""
        score = 0.0
        text = (el.get('text') or '').lower()
        classes = ' '.join(el.get('classes', [])).lower()
        identifier = f"{el.get('id', '')} {el.get('name', '')} {classes}".lower()
        
        # Goal-based scoring
        if goal == "login" or state == PageState.LOGIN:
            if el['type'] in ('email', 'password', 'text'):
                score += 60
            if 'login' in text or 'sign in' in text or 'submit' in text:
                score += 80
            if el.get('type') == 'submit':
                score += 70
        
        elif state == PageState.PRODUCT_LISTING:
            if el['tag'] == 'a' and el.get('href'):
                score += 40
            if 'product' in classes or 'item' in classes:
                score += 50
            if el.get('testId') and 'product' in (el['testId'] or '').lower():
                score += 60
        
        elif state == PageState.PRODUCT_DETAIL:
            if 'add' in text and ('cart' in text or 'basket' in text or 'bag' in text):
                score += 90
            if 'buy' in text or 'purchase' in text:
                score += 80
            if 'add-to-cart' in identifier or 'addtocart' in identifier:
                score += 85
        
        elif state == PageState.CART:
            if 'checkout' in text or 'proceed' in text:
                score += 90
            if 'continue' in text or 'next' in text:
                score += 60
        
        # Generic scoring
        if el['tag'] == 'button':
            score += 20
        if el.get('type') == 'submit':
            score += 30
        if 'primary' in classes or 'cta' in classes or 'btn-primary' in classes:
            score += 25
        if el.get('ariaLabel'):
            score += 5
        
        # Penalize destructive actions
        if any(w in text for w in ['delete', 'remove', 'cancel', 'logout', 'sign out']):
            score -= 50
        
        return max(score, 0)
    
    def _element_to_action(self, el: Dict) -> Optional[Action]:
        """Convert element descriptor to action"""
        selector = self._build_selector(el)
        if not selector:
            return None
        
        if el['tag'] == 'a' and el.get('href'):
            return Action(type="click", selector=selector, metadata={'href': el['href']})
        elif el['tag'] in ('input', 'textarea'):
            if el['type'] in ('text', 'email', 'search', 'tel'):
                return Action(type="fill", selector=selector, value="test_input")
            elif el['type'] == 'password':
                return Action(type="fill", selector=selector, value="TestPass123!")
            elif el['type'] in ('submit', 'button'):
                return Action(type="click", selector=selector)
            elif el['type'] == 'checkbox':
                return Action(type="check", selector=selector)
            elif el['type'] == 'radio':
                return Action(type="click", selector=selector)
        elif el['tag'] in ('button', 'select'):
            return Action(type="click" if el['tag'] == 'button' else "select", selector=selector)
        
        return Action(type="click", selector=selector)
    
    def _build_selector(self, el: Dict) -> Optional[str]:
        """Build a reliable CSS selector"""
        if el.get('testId'):
            return f"[data-testid='{el['testId']}']"
        if el.get('id'):
            return f"#{el['id']}"
        if el.get('name'):
            return f"{el['tag']}[name='{el['name']}']"
        if el.get('ariaLabel'):
            return f"[aria-label='{el['ariaLabel']}']"
        if el.get('classes'):
            cls = el['classes'][0]
            if cls and not cls.startswith('css-'):
                return f"{el['tag']}.{cls}"
        return None
    
    def record_outcome(self, state_key: str, action: Action, success: bool):
        """Record action outcome for learning"""
        if state_key not in self.patterns:
            self.patterns[state_key] = []
            self.success_rates[state_key] = []
        
        # Move successful actions to front
        if success:
            if action in self.patterns[state_key]:
                self.patterns[state_key].remove(action)
            self.patterns[state_key].insert(0, action)
        else:
            if action not in self.patterns[state_key]:
                self.patterns[state_key].append(action)
        
        self.success_rates[state_key].append(success)
        # Keep bounded
        if len(self.success_rates[state_key]) > 100:
            self.success_rates[state_key] = self.success_rates[state_key][-100:]

# ============ AUTOMATION ENGINE ============

class AutomationEngine:
    """Main automation engine with login, navigation, and action execution"""
    
    def __init__(
        self,
        headless: bool = True,
        credentials: Optional[Dict[str, str]] = None
    ):
        self.headless = headless
        self.credentials = credentials or {}
        self.interceptor = NetworkInterceptor()
        self.predictor = ActionPredictor()
        self.browser: Optional[Browser] = None
        self.playwright = None
    
    async def __aenter__(self):
        self.playwright = await async_playwright().start()
        self.browser = await self.playwright.chromium.launch(
            headless=self.headless,
            args=['--disable-blink-features=AutomationControlled']
        )
        return self
    
    async def __aexit__(self, *args):
        if self.browser:
            await self.browser.close()
        if self.playwright:
            await self.playwright.stop()
        self.predictor.save_model()
    
    async def create_page(self) -> Page:
        """Create a new page with proper context"""
        context = await self.browser.new_context(
            viewport={'width': 1920, 'height': 1080},
            user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
                       '(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        )
        page = await context.new_page()
        await self.interceptor.start_interception(page)
        return page
    
    async def login(
        self,
        page: Page,
        login_url: str,
        username_selector: str = None,
        password_selector: str = None,
        submit_selector: str = None
    ) -> bool:
        """Automated login flow"""
        logger.info(f"Attempting login at {login_url}")
        
        try:
            await page.goto(login_url, wait_until='networkidle', timeout=30000)
            
            # Auto-detect selectors if not provided
            if not username_selector:
                username_selector = await self._find_field(page, ['email', 'username', 'login'])
            if not password_selector:
                password_selector = await self._find_field(page, ['password'])
            if not submit_selector:
                submit_selector = await self._find_submit(page)
            
            if not all([username_selector, password_selector]):
                logger.error("Could not detect login fields")
                return False
            
            await page.fill(username_selector, self.credentials.get('username', ''))
            await page.fill(password_selector, self.credentials.get('password', ''))
            
            if submit_selector:
                await page.click(submit_selector)
            else:
                await page.press(password_selector, 'Enter')
            
            await page.wait_for_load_state('networkidle', timeout=15000)
            
            success = await self._verify_login(page)
            logger.info(f"Login {'successful' if success else 'failed'}")
            return success
            
        except Exception as e:
            logger.error(f"Login error: {e}")
            return False
    
    async def _find_field(self, page: Page, keywords: List[str]) -> Optional[str]:
        """Find form field by keywords"""
        for keyword in keywords:
            for selector in [
                f"input[name*='{keyword}' i]",
                f"input[id*='{keyword}' i]",
                f"input[type='{keyword}' i]",
                f"input[placeholder*='{keyword}' i]",
                f"input[autocomplete='{keyword}']"
            ]:
                if await page.query_selector(selector):
                    return selector
        return None
    
    async def _find_submit(self, page: Page) -> Optional[str]:
        """Find submit button"""
        for selector in [
            "button[type='submit']",
            "input[type='submit']",
            "button:has-text('Sign in')",
            "button:has-text('Login')",
            "button:has-text('Log in')",
            "button:has-text('Continue')"
        ]:
            if await page.query_selector(selector):
                return selector
        return None
    
    async def _verify_login(self, page: Page) -> bool:
        """Verify login success"""
        state = await PageAnalyzer.detect_page_state(page)
        if state == PageState.LOGIN:
            return False
        # Check for common logged-in indicators
        for selector in [
            "[class*='avatar']",
            "[class*='profile']",
            "[class*='account']",
            "button:has-text('Logout')",
            "a:has-text('Logout')",
            "a:has-text('Sign out')"
        ]:
            if await page.query_selector(selector):
                return True
        return True
    
    async def execute_action(self, page: Page, action: Action) -> bool:
        """Execute a single action"""
        try:
            if action.type == "click":
                await page.click(action.selector, timeout=5000)
            elif action.type == "fill":
                await page.fill(action.selector, str(action.value or ""))
            elif action.type == "select":
                await page.select_option(action.selector, action.value)
            elif action.type == "check":
                await page.check(action.selector)
            elif action.type == "navigate":
                await page.goto(action.url, wait_until='networkidle')
            elif action.type == "scroll":
                await page.mouse.wheel(0, action.value or 500)
            elif action.type == "wait":
                await asyncio.sleep(action.wait_time or 1)
            else:
                return False
            
            await asyncio.sleep(0.5)  # Let page settle
            return True
            
        except Exception as e:
            logger.debug(f"Action failed: {action.type} {action.selector} - {e}")
            return False
    
    async def run_loop(
        self,
        url: str,
        goal: str = "explore",
        max_iterations: int = 100,
        target_accuracy: float = 0.90,
        accuracy_window: int = 20,
        login_first: bool = False,
        login_url: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Main loop: navigates, predicts, executes, evaluates.
        Repeats from first to last action if accuracy not met.
        """
        page = await self.create_page()
        results = {
            "iterations": 0,
            "actions_taken": 0,
            "successful_actions": 0,
            "accuracy_history": [],
            "final_accuracy": 0.0,
            "achieved_target": False,
            "errors": []
        }
        
        try:
            await page.goto(url, wait_until='networkidle', timeout=30000)
            
            if login_first and self.credentials:
                await self.login(page, login_url or url)
            
            outcomes_window = deque(maxlen=accuracy_window)
            iteration = 0
            state_key = ""
            
            while iteration < max_iterations:
                iteration += 1
                results["iterations"] = iteration
                
                # Detect current state
                page_state = await PageAnalyzer.detect_page_state(page)
                elements = await PageAnalyzer.extract_interactive_elements(page)
                state_key = self.predictor._state_key(page_state, elements)
                
                # Predict next action
                prediction = await self.predictor.predict_next_action(page, goal, page_state)
                action = prediction.action
                
                logger.info(
                    f"[{iteration}] State={page_state.value} "
                    f"Action={action.type} "
                    f"Confidence={prediction.confidence:.2f}"
                )
                
                # Execute
                success = await self.execute_action(page, action)
                
                # Evaluate: did page state change as expected?
                new_state = await PageAnalyzer.detect_page_state(page)
                state_changed = new_state != page_state
                effective = success and (state_changed or action.type in ('fill', 'check'))
                
                outcomes_window.append(effective)
                results["actions_taken"] += 1
                if effective:
                    results["successful_actions"] += 1
                
                # Record for learning
                if state_key:
                    self.predictor.record_outcome(state_key, action, effective)
                
                # Compute rolling accuracy
                if len(outcomes_window) >= accuracy_window:
                    accuracy = sum(outcomes_window) / len(outcomes_window)
                    results["accuracy_history"].append(accuracy)
                    results["final_accuracy"] = accuracy
                    
                    logger.info(f"Rolling accuracy: {accuracy:.2%}")
                    
                    if accuracy >= target_accuracy:
                        results["achieved_target"] = True
                        logger.info(f"Target accuracy {target_accuracy:.0%} achieved!")
                        break
                    
                    # If dropping, reset loop (go back to start)
                    if accuracy < target_accuracy * 0.5:
                        logger.warning("Accuracy dropped significantly, restarting loop")
                        self.predictor.save_model()
                        await page.goto(url, wait_until='networkidle')
                        outcomes_window.clear()
                
                # Safety: if stuck (no state change for 10 actions), navigate home
                if len(outcomes_window) == accuracy_window and not any(outcomes_window):
                    logger.warning("Stuck, navigating back to start")
                    await page.goto(url, wait_until='networkidle')
                    outcomes_window.clear()
                    
        except Exception as e:
            logger.error(f"Loop error: {e}")
            results["errors"].append(str(e))
        
        finally:
            # Save network capture
            self.interceptor.save_capture("network_capture.json")
            self.predictor.save_model()
            await page.close()
        
        return results

# ============ MAIN ENTRY POINT ============

async def main():
    """Main entry point - the build loop"""

    target_url = input("Enter the domain to automate: ").strip()
    if not target_url.startswith(("http://", "https://")):
        target_url = f"https://{target_url}"
    target_url = target_url.rstrip("/")
    
    config = {
        "target_url": target_url,
        "login_url": f"{target_url}/login",
        "credentials": {
            "username": "your_username",
            "password": "your_password"
        },
        "goal": "navigate_and_interact",
        "max_iterations": 200,
        "target_accuracy": 0.90,
        "headless": False,  # Set True for production
        "login_first": True
    }
    
    # The loop: keeps running until 90%+ accuracy
    attempt = 0
    max_attempts = 5
    
    async with AutomationEngine(
        headless=config["headless"],
        credentials=config["credentials"]
    ) as engine:
        
        while attempt < max_attempts:
            attempt += 1
            logger.info(f"\n{'='*60}")
            logger.info(f"ATTEMPT {attempt}/{max_attempts}")
            logger.info(f"{'='*60}\n")
            
            results = await engine.run_loop(
                url=config["target_url"],
                goal=config["goal"],
                max_iterations=config["max_iterations"],
                target_accuracy=config["target_accuracy"],
                login_first=config["login_first"],
                login_url=config["login_url"]
            )
            
            print(json.dumps(results, indent=2))
            
            if results["achieved_target"]:
                logger.info(f"✓ SUCCESS on attempt {attempt}")
                break
            else:
                logger.warning(
                    f"✗ Attempt {attempt} reached only "
                    f"{results['final_accuracy']:.2%}, retrying..."
                )
                await asyncio.sleep(2)


if __name__ == "__main__":
    asyncio.run(main())