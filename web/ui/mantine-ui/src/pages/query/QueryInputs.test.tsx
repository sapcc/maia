// Copyright The Prometheus Authors

import { PropsWithChildren } from "react";
import { MantineProvider } from "@mantine/core";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import ExpressionInput from "./ExpressionInput";
import RangeInput from "./RangeInput";

vi.mock("../../state/settingsSlice", () => ({
  useSettings: () => ({
    pathPrefix: "/prometheus",
    enableAutocomplete: false,
    enableLinter: false,
  }),
}));
vi.mock("../../state/hooks", () => ({
  useAppSelector: () => ({ queryHistory: [] }),
}));
vi.mock("./MetricsExplorer/MetricsExplorer", () => ({ default: () => null }));
vi.mock("@uiw/react-codemirror", async (original) => ({
  ...(await original<typeof import("@uiw/react-codemirror")>()),
  default: ({
    value,
    onChange,
  }: {
    value: string;
    onChange: (value: string) => void;
  }) => (
    <textarea
      aria-label="Expression"
      value={value}
      onChange={(event) => onChange(event.target.value)}
    />
  ),
}));

let client: QueryClient;
const wrapper = ({ children }: PropsWithChildren) => (
  <MantineProvider env="test">
    <QueryClientProvider client={client}>{children}</QueryClientProvider>
  </MantineProvider>
);
const props = {
  initialExpr: "up+1",
  metricNames: [],
  executeQuery: vi.fn(),
  duplicatePanel: vi.fn(),
  removePanel: vi.fn(),
};

beforeEach(() => {
  client = new QueryClient();
  vi.stubGlobal(
    "matchMedia",
    vi.fn().mockReturnValue({
      matches: false,
      addEventListener: vi.fn(),
      removeEventListener: vi.fn(),
    }),
  );
  vi.stubGlobal(
    "ResizeObserver",
    class {
      observe() {}
      unobserve() {}
      disconnect() {}
    },
  );
});
afterEach(() => {
  cleanup();
  client.clear();
  vi.clearAllMocks();
  vi.unstubAllGlobals();
});

describe("query input drafts", () => {
  it("preserves expression edits and focus until the initial expression changes", () => {
    const { rerender } = render(<ExpressionInput {...props} />, { wrapper });
    const editor = screen.getByRole("textbox", { name: "Expression" });
    editor.focus();
    fireEvent.change(editor, { target: { value: "draft" } });
    rerender(<ExpressionInput {...props} metricNames={["up"]} />);
    expect(editor).toHaveValue("draft");
    expect(editor).toHaveFocus();
    rerender(<ExpressionInput {...props} initialExpr="new" />);
    expect(screen.getByRole("textbox", { name: "Expression" })).toBe(editor);
    expect(editor).toHaveValue("new");
    expect(editor).toHaveFocus();
  });

  it("preserves range drafts, resets changed props, and recovers invalid input", () => {
    const onChangeRange = vi.fn();
    const { rerender } = render(
      <RangeInput range={60000} onChangeRange={onChangeRange} />,
      { wrapper },
    );
    const input = screen.getByRole("textbox", { name: "Range" });
    input.focus();
    fireEvent.change(input, { target: { value: "2m" } });
    rerender(<RangeInput range={60000} onChangeRange={onChangeRange} />);
    expect(input).toHaveValue("2m");
    fireEvent.keyDown(input, { key: "Enter" });
    expect(onChangeRange).toHaveBeenLastCalledWith(120000);
    rerender(<RangeInput range={300000} onChangeRange={onChangeRange} />);
    expect(input).toHaveValue("5m");
    expect(input).toHaveFocus();
    fireEvent.change(input, { target: { value: "invalid" } });
    fireEvent.blur(input);
    expect(input).toHaveValue("5m");
    fireEvent.click(screen.getByRole("button", { name: "Increase range" }));
    expect(onChangeRange).toHaveBeenLastCalledWith(900000);
    fireEvent.click(screen.getByRole("button", { name: "Decrease range" }));
    expect(onChangeRange).toHaveBeenLastCalledWith(60000);
  });
});
