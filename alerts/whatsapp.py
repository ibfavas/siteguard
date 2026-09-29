"""
WhatsApp alert stub — NOT IMPLEMENTED.

TODO: integrate the WhatsApp Business Cloud API (or an approved BSP) here.
Steps when implementing:
  1. Create a Meta developer app, add the WhatsApp product, get a phone
     number ID and a permanent access token.
  2. Fill WHATSAPP_* values in config.py.
  3. Replace the body of send_whatsapp_alert() below with a POST to
     https://graph.facebook.com/v21.0/<PHONE_NUMBER_ID>/messages
     using a pre-approved message template (Meta requires templates for
     business-initiated messages).
  4. Handle 24-hour messaging-window rules and opt-in requirements.

Until then this function only logs, and always returns False. The scanner
never depends on it.
"""

import logging

import config

log = logging.getLogger("siteguard.alerts.whatsapp")


def send_whatsapp_alert(message):
    """
    Send a WhatsApp alert to the configured recipient.

    Returns True on success, False otherwise. Currently a stub: always
    returns False and logs a reminder that the integration is pending.
    """
    # TODO: WhatsApp Business API integration (see module docstring).
    if not config.WHATSAPP_ENABLED:
        log.info("WhatsApp alert skipped: WHATSAPP_ENABLED is False "
                 "(integration not implemented yet). Message was: %.120s", message)
        return False
    log.warning("WhatsApp alert requested but the API integration is a stub. "
                "Message was: %.120s", message)
    return False
