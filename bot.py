"""
Core bot logic — polls mentions, processes them through the Venice AI pipeline.
"""
import logging
import time
import requests
from datetime import datetime, timezone, timedelta
from typing import List, Optional, Tuple

import tweepy

from config import Config
from state import State
from clients import get_twitter_client
from twitter_client import get_mentions, reply_to_tweet, get_tweet_by_id
from venice_api import analyse, craft_tweet
from image_processor import process_tweet_media
from utils import extract_urls_from_entities

logger = logging.getLogger(__name__)


class VeniceBot:
    def __init__(self):
        logger.info("Initializing Venice X Bot …")
        self.state = State()
        self.state.load()
        self.client = get_twitter_client()
        self.bot_id = self._fetch_bot_id()
        self.session_start = datetime.now(timezone.utc)

        # Rate-limit bookkeeping
        self.last_check = 0.0
        self.hourly_replies = 0
        self.hourly_reset = time.time()
        self._backoff = 1
        logger.info("Bot ready.")

    # ── Helpers ──────────────────────────────────────────────────

    def _fetch_bot_id(self) -> int:
        """Get our own user ID (with one rate-limit retry)."""
        for attempt in range(2):
            try:
                me = self.client.get_me()
                if me and me.data:
                    logger.info(f"Bot user ID: {me.data.id}")
                    return me.data.id
                raise RuntimeError("get_me() returned no data")
            except tweepy.errors.TooManyRequests as e:
                if attempt == 0:
                    self._wait_for_rate_limit(e)
                else:
                    raise
        raise RuntimeError("Could not fetch bot user ID")

    def _wait_for_rate_limit(self, exc: tweepy.errors.TooManyRequests):
        reset = int(exc.response.headers.get("x-rate-limit-reset", 0))
        now = time.time()
        wait = max(reset - now + 5, 60)
        logger.warning(f"Rate limited. Sleeping {wait:.0f}s …")
        time.sleep(wait)

    def _backoff_sleep(self, base: float = None):
        base = base or Config.MIN_CHECK_INTERVAL
        wait = min(base * self._backoff, 900)
        logger.warning(f"Backing off {wait:.0f}s (×{self._backoff})")
        time.sleep(wait)
        self._backoff = min(self._backoff * 2, 16)

    def _reset_backoff(self):
        self._backoff = 1

    def _tick_hourly(self):
        if time.time() - self.hourly_reset >= 3600:
            logger.info(f"Hourly reset ({self.hourly_replies} replies this hour)")
            self.hourly_replies = 0
            self.hourly_reset = time.time()

    def _tweet_age_ok(self, tweet) -> bool:
        """Return True if tweet is recent enough to reply to."""
        created = getattr(tweet, "created_at", None)
        if created is None:
            return False
        if isinstance(created, str):
            try:
                created = datetime.fromisoformat(created.replace("Z", "+00:00"))
            except Exception:
                return False
        age = datetime.now(timezone.utc) - created
        if age > timedelta(minutes=Config.MAX_TWEET_AGE_MINUTES):
            logger.debug(f"Tweet {tweet.id} too old ({age})")
            return False
        return True

    # ── Context extraction ───────────────────────────────────────

    def _extract_context(
        self, tweet, media_lookup: dict
    ) -> Tuple[Optional[str], List[bytes], List[str]]:
        """Pull context text, images, and URLs from quote tweets & conversation parents."""
        ctx_text = None
        ctx_images: List[bytes] = []
        ctx_urls: List[str] = []

        # URLs from the mention itself
        ctx_urls.extend(extract_urls_from_entities(getattr(tweet, "entities", None)))

        # Quote tweets
        refs = getattr(tweet, "referenced_tweets", None) or []
        for ref in refs:
            if ref.type == "quoted":
                try:
                    resp = get_tweet_by_id(self.client, ref.id)
                    if resp and resp.data:
                        ctx_text = resp.data.text
                        ctx_urls.extend(
                            extract_urls_from_entities(getattr(resp.data, "entities", None))
                        )
                        ctx_images.extend(self._images_from_response(resp))
                except tweepy.errors.TooManyRequests as e:
                    self._wait_for_rate_limit(e)
                    break
                except Exception as e:
                    logger.warning(f"Error fetching quoted tweet {ref.id}: {e}")

        # Reply chain context — fetch both immediate parent AND conversation root
        # This ensures the bot understands the full context of deep thread replies
        refs = getattr(tweet, "referenced_tweets", None) or []
        replied_to_id = None
        for ref in refs:
            if ref.type == "replied_to":
                replied_to_id = ref.id
                break

        is_followup = getattr(tweet, "in_reply_to_user_id", None) == self.bot_id

        # 1. Fetch immediate parent (the tweet this is replying to)
        if replied_to_id and replied_to_id != tweet.id:
            try:
                parent = get_tweet_by_id(self.client, replied_to_id)
                if parent and parent.data:
                    parent_text = parent.data.text
                    if is_followup:
                        ctx_text = f"[CONTINUING] {parent_text}"
                    else:
                        ctx_text = parent_text if not ctx_text else f"{ctx_text}\n\n[REPLYING TO]: {parent_text}"
                    ctx_urls.extend(
                        extract_urls_from_entities(getattr(parent.data, "entities", None))
                    )
                    ctx_images.extend(self._images_from_response(parent))
            except tweepy.errors.TooManyRequests as e:
                self._wait_for_rate_limit(e)
            except Exception as e:
                logger.warning(f"Error fetching parent tweet {replied_to_id}: {e}")

        # 2. Also fetch conversation root if different from immediate parent
        #    (provides full thread context for deep replies)
        if (tweet.conversation_id and 
            tweet.conversation_id != tweet.id and 
            tweet.conversation_id != replied_to_id):
            try:
                root = get_tweet_by_id(self.client, tweet.conversation_id)
                if root and root.data:
                    root_text = root.data.text
                    ctx_text = f"[THREAD ROOT]: {root_text}\n\n{ctx_text}" if ctx_text else f"[THREAD ROOT]: {root_text}"
                    ctx_urls.extend(
                        extract_urls_from_entities(getattr(root.data, "entities", None))
                    )
                    ctx_images.extend(self._images_from_response(root))
            except tweepy.errors.TooManyRequests as e:
                self._wait_for_rate_limit(e)
            except Exception as e:
                logger.warning(f"Error fetching thread root {tweet.conversation_id}: {e}")

        return ctx_text, ctx_images, list(dict.fromkeys(ctx_urls))

    @staticmethod
    def _images_from_response(resp) -> List[bytes]:
        """Download photo media from a tweet response's includes."""
        images = []
        data = resp.data
        if not (hasattr(data, "attachments") and data.attachments):
            return images
        keys = data.attachments.get("media_keys", [])
        media_list = (resp.includes or {}).get("media", [])
        lookup = {m.media_key: m for m in media_list}
        for key in keys:
            media = lookup.get(key)
            if media and media.type == "photo" and getattr(media, "url", None):
                try:
                    r = requests.get(media.url, timeout=10)
                    if r.ok:
                        images.append(r.content)
                except Exception:
                    pass
        return images

    # ── Processing ───────────────────────────────────────────────

    def _process_tweet(self, tweet, media_lookup: dict, user_lookup: dict):
        if self.state.is_processed(tweet.id):
            return

        author = user_lookup.get(tweet.author_id)
        if not author or author.protected or author.id == self.bot_id:
            self.state.add_tweet(tweet.id)
            return

        # Enforce single-author conversations
        allowed = self.state.get_allowed_author(tweet.conversation_id)
        if allowed and str(tweet.author_id) != str(allowed):
            self.state.add_tweet(tweet.id)
            return

        if not self._tweet_age_ok(tweet):
            self.state.add_tweet(tweet.id)
            return

        # ── Gather context ──
        ctx_text, ctx_images, ctx_urls = self._extract_context(tweet, media_lookup)

        # ── Media from the mention itself ──
        try:
            img_bytes, img_url = process_tweet_media(tweet, media_lookup)
        except Exception:
            img_bytes, img_url = None, None

        if not img_bytes and ctx_images:
            img_bytes = ctx_images[0]
            img_url = None

        # ── Generate reply ──
        query = tweet.text.replace("@venice_bot", "").replace("@venice_mind", "").strip()

        analysis = analyse(
            query,
            context=ctx_text,
            image_bytes=img_bytes,
            image_url=img_url,
            urls=ctx_urls,
        )
        if analysis == Config.ERROR_MESSAGE:
            logger.warning(f"Analysis failed for tweet {tweet.id}")
            return

        use_vision = bool(img_bytes or img_url)
        final = craft_tweet(analysis, use_vision=use_vision, context_urls=ctx_urls)
        if not final or final == Config.ERROR_MESSAGE:
            logger.warning(f"Crafting failed for tweet {tweet.id}")
            return

        # ── Post reply ──
        try:
            resp = reply_to_tweet(self.client, tweet.id, final)
            if resp:
                self.hourly_replies += 1
                if not self.state.get_allowed_author(tweet.conversation_id):
                    self.state.set_allowed_author(tweet.conversation_id, tweet.author_id)
                self.state.add_tweet(tweet.id)
                logger.info(f"✅ Replied to tweet {tweet.id}")
            else:
                logger.warning(f"Reply returned None for tweet {tweet.id}")
        except tweepy.errors.TooManyRequests as e:
            self._wait_for_rate_limit(e)
        except Exception as e:
            logger.error(f"Error posting reply: {e}")

        time.sleep(Config.TWEET_DELAY)

    # ── Main loop ────────────────────────────────────────────────

    def process_mentions(self):
        # Rate-limit pacing
        elapsed = time.time() - self.last_check
        if elapsed < Config.MIN_CHECK_INTERVAL:
            time.sleep(Config.MIN_CHECK_INTERVAL - elapsed)

        self._tick_hourly()
        if self.hourly_replies >= Config.MAX_REPLIES_PER_HOUR:
            logger.warning("Hourly reply cap reached.")
            return

        # Lookback window
        if Config.USE_SESSION_START_CUTOFF:
            cutoff = max(
                self.session_start,
                datetime.now(timezone.utc) - timedelta(minutes=Config.MAX_TWEET_AGE_MINUTES),
            )
        else:
            cutoff = datetime.now(timezone.utc) - timedelta(minutes=Config.MAX_TWEET_AGE_MINUTES)

        start_time = cutoff.strftime("%Y-%m-%dT%H:%M:%S.") + f"{cutoff.microsecond // 1000:03d}Z"

        try:
            mentions = get_mentions(self.client, self.bot_id, start_time=start_time)
            self.last_check = time.time()

            if not mentions or not mentions.data:
                logger.info("No new mentions.")
                self._reset_backoff()
                return

            includes = mentions.includes or {}
            media_lookup = {m.media_key: m for m in includes.get("media", [])}
            user_lookup = {u.id: u for u in includes.get("users", [])}

            logger.info(f"Processing {len(mentions.data)} mention(s) …")
            for tweet in reversed(mentions.data):
                # Session cutoff guard
                if Config.USE_SESSION_START_CUTOFF:
                    created = getattr(tweet, "created_at", None)
                    if created:
                        try:
                            dt = (
                                created
                                if not isinstance(created, str)
                                else datetime.fromisoformat(created.replace("Z", "+00:00"))
                            )
                            if dt < self.session_start:
                                self.state.add_tweet(tweet.id)
                                continue
                        except Exception:
                            pass

                try:
                    self._process_tweet(tweet, media_lookup, user_lookup)
                except Exception as e:
                    logger.error(f"Unhandled error on tweet {tweet.id}: {e}", exc_info=True)
                    self.state.add_tweet(tweet.id)

            self._reset_backoff()

        except tweepy.errors.TooManyRequests as e:
            self._wait_for_rate_limit(e)
        except tweepy.errors.TweepyException as e:
            logger.error(f"Twitter API error: {e}")
            self._backoff_sleep()
        except Exception as e:
            logger.error(f"Unexpected error: {e}", exc_info=True)
            self._backoff_sleep()

    def run(self):
        logger.info("Venice X Bot is live. 🚀")
        while True:
            try:
                self.process_mentions()
                self.state.save()
            except KeyboardInterrupt:
                logger.info("Shutting down …")
                self.state.save()
                break
            except Exception as e:
                logger.critical(f"Critical error in main loop: {e}", exc_info=True)
                time.sleep(60)
