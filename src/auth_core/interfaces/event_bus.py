"""
Event bus interface for auth-core package.

Defines the contract for publishing and subscribing to domain events.
"""

from abc import ABC, abstractmethod
from typing import Any, Callable


class IEventBus(ABC):
    """Abstract interface for event bus."""

    @abstractmethod
    def publish(self, event: Any) -> None:
        """
        Publish an event.

        Args:
            event: The event to publish
        """
        pass

    @abstractmethod
    def subscribe(self, event_type: type, handler: Callable[[Any], None]) -> None:
        """
        Subscribe to an event type.

        Args:
            event_type: The event type to subscribe to
            handler: The handler function to call when event is published
        """
        pass

    @abstractmethod
    def unsubscribe(self, event_type: type, handler: Callable[[Any], None]) -> None:
        """
        Unsubscribe from an event type.

        Args:
            event_type: The event type to unsubscribe from
            handler: The handler function to remove
        """
        pass
