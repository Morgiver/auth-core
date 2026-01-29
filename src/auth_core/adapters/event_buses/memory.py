"""
In-memory event bus implementation.

Simple synchronous event bus for testing and development.
"""

import logging
from collections import defaultdict
from typing import Any, Callable, Dict, List

from auth_core.interfaces.event_bus import IEventBus

logger = logging.getLogger(__name__)


class InMemoryEventBus(IEventBus):
    """
    In-memory event bus implementation.

    Events are published synchronously to all subscribers.
    """

    def __init__(self) -> None:
        self._subscribers: Dict[type, List[Callable[[Any], None]]] = defaultdict(list)

    def publish(self, event: Any) -> None:
        """
        Publish an event to all subscribers.

        Args:
            event: The event to publish
        """
        event_type = type(event)
        subscribers = self._subscribers.get(event_type, [])

        logger.debug(f"Publishing event: {event_type.__name__} to {len(subscribers)} subscribers")

        for handler in subscribers:
            try:
                handler(event)
            except Exception as e:
                logger.error(
                    f"Error in event handler for {event_type.__name__}: {str(e)}",
                    exc_info=True,
                )

    def subscribe(self, event_type: type, handler: Callable[[Any], None]) -> None:
        """
        Subscribe to an event type.

        Args:
            event_type: The event type to subscribe to
            handler: The handler function to call when event is published
        """
        if handler not in self._subscribers[event_type]:
            self._subscribers[event_type].append(handler)
            logger.debug(f"Subscribed handler to {event_type.__name__}")

    def unsubscribe(self, event_type: type, handler: Callable[[Any], None]) -> None:
        """
        Unsubscribe from an event type.

        Args:
            event_type: The event type to unsubscribe from
            handler: The handler function to remove
        """
        if handler in self._subscribers[event_type]:
            self._subscribers[event_type].remove(handler)
            logger.debug(f"Unsubscribed handler from {event_type.__name__}")
