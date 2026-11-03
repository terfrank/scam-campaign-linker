"""Parse HTML into the few facts collectors need, using the standard-library parser.

html.parser only tokenises text: it never runs scripts, loads resources or follows links.
"""

from dataclasses import dataclass
from html.parser import HTMLParser

LINK_ATTRIBUTES = ("href", "src", "action")


@dataclass(frozen=True)
class ParsedPage:
    title: str | None
    tags: tuple[str, ...]  # start tags in document order, e.g. ('html', 'head', 'title', ...)
    icon_hrefs: tuple[str, ...]  # href of every <link rel="... icon ...">
    links: tuple[str, ...]  # every href/src/action value, exactly as written


class _PageParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.tags: list[str] = []
        self.icon_hrefs: list[str] = []
        self.links: list[str] = []
        self.title_parts: list[str] = []
        self._in_title = False
        self._title_done = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.tags.append(tag)
        values = {name: value for name, value in attrs if value is not None}
        self.links.extend(values[name] for name in LINK_ATTRIBUTES if name in values)
        if tag == "link" and "icon" in values.get("rel", "").lower().split() and "href" in values:
            self.icon_hrefs.append(values["href"])
        if tag == "title" and not self._title_done:
            self._in_title = True

    def handle_endtag(self, tag: str) -> None:
        if tag == "title" and self._in_title:
            self._in_title = False
            self._title_done = True

    def handle_data(self, data: str) -> None:
        if self._in_title:
            self.title_parts.append(data)


def parse_html(html: str) -> ParsedPage:
    """Extract title, tag sequence, icon links and all link targets from an HTML string."""
    parser = _PageParser()
    parser.feed(html)
    parser.close()
    title = "".join(parser.title_parts) if parser.title_parts else None
    return ParsedPage(
        title=title,
        tags=tuple(parser.tags),
        icon_hrefs=tuple(parser.icon_hrefs),
        links=tuple(parser.links),
    )
