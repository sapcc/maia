// SPDX-FileCopyrightText: 2026 SAP SE or an SAP affiliate company
// SPDX-License-Identifier: Apache-2.0

import { render, screen, waitFor, fireEvent, cleanup } from "@testing-library/react";
import { MaiaProjectProvider } from "./MaiaProjectContext";
import { afterEach, expect, test, vi } from "vitest";

vi.mock("../state/settingsSlice", () => ({
  useSettings: () => ({ pathPrefix: "/domain/project/metrics/maia/ui" }),
}));
vi.mock("@mantine/core", () => ({
  Alert: ({ children }: { children: React.ReactNode }) => <div role="alert">{children}</div>,
  Button: ({ children, onClick }: { children: React.ReactNode; onClick: () => void }) => <button onClick={onClick}>{children}</button>,
  Center: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
  Stack: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
  Loader: () => <span>Loading</span>,
}));

afterEach(() => { cleanup(); vi.unstubAllGlobals(); });

test("proxied 401 displays recovery instructions and permits retry without a Maia login redirect", async () => {
  const originalLocation = window.location.href;
  const fetch = vi.fn().mockImplementation(async () => new Response("Unauthorized", { status: 401 }));
  vi.stubGlobal("fetch", fetch);
  render(<MaiaProjectProvider><div>Query UI</div></MaiaProjectProvider>);
  expect(await screen.findByRole("alert")).toHaveTextContent("Sign in to the hosting dashboard again");
  expect(window.location.href).toBe(originalLocation);
  expect(screen.queryByText("Query UI")).not.toBeInTheDocument();
  expect(fetch.mock.calls.map(([url]) => url)).toEqual([
    "/domain/project/metrics/maia/api/v1/whoami",
    "/domain/project/metrics/maia/api/v1/projects",
  ]);
  fetch.mockImplementation(async (url: string) => new Response(JSON.stringify(
    url.endsWith("whoami") ? { projectId: "project" } : [{ id: "project", name: "Project" }]
  )));
  fireEvent.click(screen.getByRole("button", { name: "Retry" }));
  await waitFor(() => expect(screen.getByText("Query UI")).toBeInTheDocument());
});
