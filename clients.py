"""Twitter client initialization."""
import logging
import tweepy
from config import Config

logger = logging.getLogger(__name__)


def get_twitter_client() -> tweepy.Client:
    Config.validate()
    client = tweepy.Client(
        bearer_token=Config.TWITTER_BEARER_TOKEN,
        consumer_key=Config.TWITTER_API_KEY,
        consumer_secret=Config.TWITTER_API_SECRET,
        access_token=Config.TWITTER_ACCESS_TOKEN,
        access_token_secret=Config.TWITTER_ACCESS_TOKEN_SECRET,
        wait_on_rate_limit=False,
    )
    logger.info("Twitter client ready.")
    return client
