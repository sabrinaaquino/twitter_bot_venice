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
from venice_knowledge import validate_configured_models
from image_processor import process_tweet_media
from utils import extract_urls_from_entities

logger = logging.getLogger(__name__)


class VeniceBot:
    def __init__(self, client=None):
        logger.info("Initializing Venice X Bot …")
        self.state = State()
        self.state.load()
        # `client` is injectable so the loop can be driven by a fake client in
        # tests (offline); production passes None and builds the real one.
        self.client = client or get_twitter_client()
        self.bot_id = self._fetch_bot_id()
        self.session_start = datetime.now(timezone.utc)

        # Surface any retired/renamed model IDs at boot (Plan 0001) — better a
        # loud startup alert than silent per-reply degradation later.
        validate_configured_models()

        # Rate-limit bookkeeping
        self.last_check = 0.0
        self.hourly_replies = 0
        self.hourly_reset = time.time()
        self._backoff = 1
        
        # Per-user reply tracking (anti-spam)
        self.user_reply_counts: dict[str, int] = {}  # user_id → reply count this hour
        self.user_mention_counts: dict[str, int] = {}  # user_id → mentions seen this hour (flood detection)
        self.user_reply_reset = time.time()
        
        logger.info("Bot ready.")

    # ── Helpers ──────────────────────────────────────────────────

    def _fetch_bot_id(self) -> int:
        """Get our own user ID (with one rate-limit retry).

        If Config.BOT_USER_ID is set, use it and skip the API entirely (some X API
        tiers 402 on user lookups). Otherwise look it up: by username in DRY_RUN
        (app-only auth, where get_me() isn't available) or via get_me() in prod.
        """
        if Config.BOT_USER_ID:
            logger.info(f"Using configured bot id {Config.BOT_USER_ID}")
            return int(Config.BOT_USER_ID)

        for attempt in range(2):
            try:
                if Config.DRY_RUN:
                    resp = self.client.get_user(username=Config.BOT_USERNAME, user_auth=False)
                else:
                    resp = self.client.get_me()
                if resp and resp.data:
                    logger.info(f"Bot user ID: {resp.data.id}")
                    return resp.data.id
                raise RuntimeError("bot-id lookup returned no data")
            except tweepy.errors.TooManyRequests as e:
                if attempt == 0:
                    self._wait_for_rate_limit(e)
                else:
                    raise
            except tweepy.errors.HTTPException as e:
                # e.g. a tier that 402s on user lookups — fail cleanly with guidance
                # (ValueError is reported by main() without a traceback).
                raise ValueError(
                    f"Couldn't fetch the bot's user id from X ({e}). Your API tier may "
                    f"not permit user lookups — set BOT_USER_ID in .env to skip this call."
                ) from e
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
        
        # Also reset per-user counts
        if time.time() - self.user_reply_reset >= 3600:
            self.user_reply_counts = {}
            self.user_mention_counts = {}
            self.user_reply_reset = time.time()
    
    def _is_blocked_account(self, author) -> bool:
        """Check if author is a blocked bot/spam account."""
        if not author:
            return False
        username = getattr(author, "username", None)
        if username and username.lower() in {b.lower() for b in Config.BLOCKED_ACCOUNTS}:
            logger.info(f"Blocked account ignored: @{username}")
            return True
        return False
    
    def _user_reply_limit_reached(self, user_id: str) -> bool:
        """Check if we've hit the per-user reply limit."""
        count = self.user_reply_counts.get(str(user_id), 0)
        if count >= Config.MAX_REPLIES_PER_USER_PER_HOUR:
            logger.info(f"Per-user limit reached for {user_id} ({count} replies this hour)")
            return True
        return False
    
    def _increment_user_replies(self, user_id: str):
        """Track reply to this user."""
        uid = str(user_id)
        self.user_reply_counts[uid] = self.user_reply_counts.get(uid, 0) + 1

    def _register_mention_is_flood(self, user_id: str) -> bool:
        """Count this mention and report whether the user is now flooding us."""
        from agent.guardrails import is_flood
        uid = str(user_id)
        self.user_mention_counts[uid] = self.user_mention_counts.get(uid, 0) + 1
        return is_flood(
            self.user_mention_counts[uid],
            Config.MAX_REPLIES_PER_USER_PER_HOUR,
            Config.SPAM_FLOOD_FACTOR,
        )

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

        # ── Anti-spam checks ──
        # 1. Blocked accounts (known bots)
        if self._is_blocked_account(author):
            self.state.add_tweet(tweet.id)
            return

        # 1b. Dynamic spam/security blocklist (24h TTL, auto-expiring)
        now = time.time()
        if self.state.is_blocked(tweet.author_id, now):
            logger.info(f"Blocked user {tweet.author_id} (spam/security) — not engaging")
            self.state.add_tweet(tweet.id)
            return

        # 1c. Flooding → record a spam offense (blocks them) and stop engaging
        if self._register_mention_is_flood(tweet.author_id):
            logger.warning(f"User {tweet.author_id} flooding — recording spam offense")
            self.state.record_offense(tweet.author_id, now)
            self.state.add_tweet(tweet.id)
            return

        # 2. Per-user rate limit
        if self._user_reply_limit_reached(tweet.author_id):
            self.state.add_tweet(tweet.id)
            return
        
        # 3. Verified-only mode (optional)
        if Config.VERIFIED_ONLY and not getattr(author, "verified", False):
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

        # ── Generate reply (agent path or legacy pipeline) ──
        query = tweet.text.replace("@venice_bot", "").replace("@venice_mind", "").strip()

        if Config.USE_AGENT:
            final = self._agent_reply(query, ctx_text, ctx_urls, tweet.author_id, now)
        else:
            final = self._legacy_reply(query, ctx_text, ctx_urls, img_bytes, img_url)

        if final is None:                       # silent (blocked / re-offense / failure)
            self.state.add_tweet(tweet.id)
            return
        if final == Config.ERROR_MESSAGE:        # transient — don't mark processed, retry later
            logger.warning(f"Reply generation failed for tweet {tweet.id}")
            return

        # ── Post reply (or log it in dry-run) ──
        if Config.DRY_RUN:
            logger.info(f"[DRY RUN] would reply to {tweet.id} (user {tweet.author_id}): {final}")
            self._record_reply(tweet)
            return

        try:
            resp = reply_to_tweet(self.client, tweet.id, final)
            if resp:
                self._record_reply(tweet)
                logger.info(f"Replied to tweet {tweet.id} (user {tweet.author_id}: {self.user_reply_counts.get(str(tweet.author_id), 0)} this hour)")
            else:
                logger.warning(f"Reply returned None for tweet {tweet.id}")
        except tweepy.errors.TooManyRequests as e:
            self._wait_for_rate_limit(e)
        except Exception as e:
            logger.error(f"Error posting reply: {e}")

        time.sleep(Config.TWEET_DELAY)

    # ── Reply generation paths ───────────────────────────────────

    def _legacy_reply(self, query, ctx_text, ctx_urls, img_bytes, img_url):
        """The proven two-step pipeline. Returns reply text, ERROR_MESSAGE, or None."""
        analysis = analyse(query, context=ctx_text, image_bytes=img_bytes,
                           image_url=img_url, urls=ctx_urls)
        if analysis == Config.ERROR_MESSAGE:
            return Config.ERROR_MESSAGE
        use_vision = bool(img_bytes or img_url)
        final = craft_tweet(analysis, use_vision=use_vision, context_urls=ctx_urls)
        return final or Config.ERROR_MESSAGE

    def _agent_reply(self, query, ctx_text, ctx_urls, author_id, now):
        """The ReAct agent path, with the mandatory safety guardrail + spam policy.
        Returns reply text, ERROR_MESSAGE, or None (silent: no engagement)."""
        from agent.guardrails import agent_reply, offense_reply_text
        result = agent_reply(query, context=ctx_text, urls=ctx_urls)
        if result.trip in ("injection", "scam", "spam"):
            prior = self.state.times_offended(author_id)
            self.state.record_offense(author_id, now)   # blocks 24h
            return offense_reply_text(result, prior)     # warn once, then None
        return result.text

    def _record_reply(self, tweet):
        """Bookkeeping after a (real or dry-run) reply: counts, author lock, processed."""
        self.hourly_replies += 1
        self._increment_user_replies(tweet.author_id)
        if not self.state.get_allowed_author(tweet.conversation_id):
            self.state.set_allowed_author(tweet.conversation_id, tweet.author_id)
        self.state.add_tweet(tweet.id)

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
                if not Config.DRY_RUN:
                    self.state.save()
            except KeyboardInterrupt:
                logger.info("Shutting down …")
                if not Config.DRY_RUN:
                    self.state.save()
                break
            except Exception as e:
                logger.critical(f"Critical error in main loop: {e}", exc_info=True)
                time.sleep(60)
