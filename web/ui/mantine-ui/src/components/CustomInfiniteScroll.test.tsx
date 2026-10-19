// Copyright The Prometheus Authors

import { act, cleanup, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import CustomInfiniteScroll, {
  InfiniteScrollItemsProps,
} from "./CustomInfiniteScroll";

const Items = ({ items }: InfiniteScrollItemsProps<string>) => (
  <ul>
    {items.map((item) => (
      <li key={item}>{item}</li>
    ))}
  </ul>
);
const dataset = (prefix: string, count = 130) =>
  Array.from({ length: count }, (_, i) => `${prefix}-${i}`);

// react-infinite-scroll-component v7 loads the next page when its sentinel
// intersects the viewport, so the tests drive a fake IntersectionObserver.
const observers = new Set<FakeIntersectionObserver>();
class FakeIntersectionObserver {
  constructor(private callback: IntersectionObserverCallback) {}
  observe() {
    observers.add(this);
  }
  unobserve() {}
  disconnect() {
    observers.delete(this);
  }
  takeRecords() {
    return [];
  }
  intersect() {
    this.callback(
      [{ isIntersecting: true } as IntersectionObserverEntry],
      this as unknown as IntersectionObserver,
    );
  }
}

function scrollToEnd() {
  for (const observer of [...observers]) {
    observer.intersect();
  }
}

beforeEach(() => {
  vi.stubGlobal("IntersectionObserver", FakeIntersectionObserver);
});
afterEach(() => {
  cleanup();
  observers.clear();
  vi.unstubAllGlobals();
});

describe("infinite scroll dataset changes", () => {
  it("resets paging and the widget loading latch when a new source replaces a pending page", () => {
    const first = dataset("first");
    const second = dataset("second");
    const { rerender } = render(
      <CustomInfiniteScroll allItems={first} child={Items} />,
    );
    expect(screen.getAllByRole("listitem")).toHaveLength(50);
    act(() => {
      scrollToEnd();
      rerender(<CustomInfiniteScroll allItems={second} child={Items} />);
    });
    expect(screen.getAllByRole("listitem")).toHaveLength(50);
    expect(screen.getByText("second-0")).toBeInTheDocument();
    act(() => scrollToEnd());
    expect(screen.getAllByRole("listitem")).toHaveLength(100);
    expect(screen.getByText("second-99")).toBeInTheDocument();
  });

  it.each([0, 12, 50, 51])(
    "resets an expanded list to a %i-item source",
    (count) => {
      const { rerender } = render(
        <CustomInfiniteScroll allItems={dataset("old")} child={Items} />,
      );
      act(() => scrollToEnd());
      expect(screen.getAllByRole("listitem")).toHaveLength(100);
      rerender(
        <CustomInfiniteScroll allItems={dataset("new", count)} child={Items} />,
      );
      expect(screen.queryAllByRole("listitem")).toHaveLength(
        Math.min(count, 50),
      );
      act(() => scrollToEnd());
      expect(screen.queryAllByRole("listitem")).toHaveLength(count);
    },
  );
});
